package handler

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/micro/micro/v3/proto/api"
	"github.com/micro/micro/v3/service"
	"github.com/micro/micro/v3/service/client"
	"github.com/micro/micro/v3/service/config"
	"github.com/micro/micro/v3/service/context/metadata"
	"github.com/micro/micro/v3/service/errors"
	log "github.com/micro/micro/v3/service/logger"
	"github.com/micro/micro/v3/service/store"
	pb "github.com/micro/services/email/proto"
	"github.com/micro/services/pkg/tenant"
	spampb "github.com/micro/services/spam/proto"
	"github.com/sendgrid/sendgrid-go/helpers/eventwebhook"
)

const (
	prefixUserID     = "byUserID"
	prefixSendgridID = "bySendgridID"
)

type Sent struct {
	UserID        string
	SendgridMsgID string
}

type sendgridConf struct {
	Key       string `json:"key"`
	EmailFrom string `json:"email_from"`
	PublicKey string `json:"public_key"`
	PoolName  string `json:"ip_pool_name"`
}

func NewEmailHandler(svc *service.Service) *Email {
	c := sendgridConf{}
	val, err := config.Get("sendgridapi")
	if err != nil {
		log.Warnf("Error getting config: %v", err)
	}
	err = val.Scan(&c)
	if err != nil {
		log.Warnf("Error scanning config: %v", err)
	}
	if len(c.Key) == 0 {
		log.Fatalf("Sendgrid API key not configured")
	}
	if len(c.PublicKey) == 0 {
		log.Fatalf("Sendgrid public key not configured")
	}
	sgPublicKey, err := eventwebhook.ConvertPublicKeyBase64ToECDSA(c.PublicKey)
	if err != nil {
		log.Fatalf("Failed to configure public key")
	}
	return &Email{
		c,
		spampb.NewSpamService("spam", svc.Client()),
		sgPublicKey,
	}
}

type Email struct {
	config      sendgridConf
	spamSvc     spampb.SpamService
	sgPublicKey *ecdsa.PublicKey
}

func (e *Email) Send(ctx context.Context, request *pb.SendRequest, response *pb.SendResponse) error {
	if len(request.From) == 0 {
		return errors.BadRequest("email.send.validation", "Missing from address")
	}
	if len(request.To) == 0 {
		return errors.BadRequest("email.send.validation", "Missing to address")
	}
	if len(request.Subject) == 0 {
		return errors.BadRequest("email.send.validation", "Missing subject")
	}
	if len(request.TextBody) == 0 && len(request.HtmlBody) == 0 {
		return errors.BadRequest("email.send.validation", "Missing email body")
	}

	spamReq := &spampb.ClassifyRequest{
		TextBody: request.TextBody,
		HtmlBody: request.HtmlBody,
		To:       request.To,
		From:     request.From,
		Subject:  request.Subject,
	}
	rsp, err := e.spamSvc.Classify(ctx, spamReq, client.WithAuthToken())
	if err != nil || rsp.IsSpam {
		log.Errorf("Error validating email %s %v", err, rsp)
		return errors.InternalServerError("email.send", "Error validating email")
	}

	if err := e.sendEmail(ctx, request); err != nil {
		log.Errorf("Error sending email: %v\n", err)
		return errors.InternalServerError("email.sendemail", "Error sending email")
	}

	return nil
}

// sendEmail sends an email via the sendgrid API
// Docs: https://bit.ly/2VYPQD1
func (e *Email) sendEmail(ctx context.Context, req *pb.SendRequest) error {
	content := []interface{}{}
	replyTo := e.config.EmailFrom
	if len(req.ReplyTo) > 0 {
		replyTo = req.ReplyTo
	}

	if len(req.TextBody) > 0 {
		content = append(content, map[string]string{
			"type":  "text/plain",
			"value": req.TextBody,
		})
	}

	if len(req.HtmlBody) > 0 {
		content = append(content, map[string]string{
			"type":  "text/html",
			"value": req.HtmlBody,
		})
	}

	reqMap := map[string]interface{}{
		"from": map[string]string{
			"email": e.config.EmailFrom,
			"name":  req.From,
		},
		"reply_to": map[string]string{
			"email": replyTo,
		},
		"subject": req.Subject,
		"content": content,
		"personalizations": []interface{}{
			map[string]interface{}{
				"to": []map[string]string{
					{
						"email": req.To,
					},
				},
			},
		},
	}
	if len(e.config.PoolName) > 0 {
		reqMap["ip_pool_name"] = e.config.PoolName
	}

	reqBody, _ := json.Marshal(reqMap)

	httpReq, err := http.NewRequest("POST", "https://api.sendgrid.com/v3/mail/send", bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}

	httpReq.Header.Set("Authorization", "Bearer "+e.config.Key)
	httpReq.Header.Set("Content-Type", "application/json")

	rsp, err := new(http.Client).Do(httpReq)
	if err != nil {
		return fmt.Errorf("could not send email, error: %v", err)
	}
	defer rsp.Body.Close()

	tnt, ok := tenant.FromContext(ctx)
	if ok {
		msgID := rsp.Header.Get("X-Message-ID")
		if len(msgID) > 0 {
			sent := Sent{
				UserID:        tnt,
				SendgridMsgID: msgID,
			}
			b, _ := json.Marshal(&sent)
			if err := store.Write(&store.Record{
				Key:   fmt.Sprintf("%s/%s/%s", prefixUserID, sent.UserID, sent.SendgridMsgID),
				Value: b,
			}); err != nil {
				log.Errorf("Failed to persist mapping %+v %s", sent, err)
			}
			if err := store.Write(&store.Record{
				Key:   fmt.Sprintf("%s/%s", prefixSendgridID, sent.SendgridMsgID),
				Value: b,
			}); err != nil {
				log.Errorf("Failed to persist mapping %+v %s", sent, err)
			}
		}
	}

	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		bytes, err := ioutil.ReadAll(rsp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("could not send email, error: %v", string(bytes))
	}

	return nil
}

type sendgridEvent struct {
	Email       string   `json:"email"`
	Timestamp   int      `json:"timestamp"`
	SmtpId      string   `json:"smtp-id"`
	Event       string   `json:"event"`
	Category    []string `json:"category"`
	SgEventId   string   `json:"sg_event_id"`
	SgMessageId string   `json:"sg_message_id"` // this is prefixed with X-Message-ID on /send response
	Response    string   `json:"response"`
	Attempt     string   `json:"attempt"`
	Reason      string   `json:"reason"`
	Status      string   `json:"status"`
}

func (e *Email) Webhook(ctx context.Context, req *api.Request, rsp *api.Response) error {
	md, ok := metadata.FromContext(ctx)
	if !ok {
		log.Errorf("Missing metadata from request")
		return errors.BadRequest("email.Webhook", "Missing headers")
	}
	// validate signature

	ok, err := eventwebhook.VerifySignature(e.sgPublicKey, []byte(req.Body), md["X-Twilio-Email-Event-Webhook-Signature"], md["X-Twilio-Email-Event-Webhook-Timestamp"])
	if !ok || err != nil {
		log.Errorf("Failed to verify signature %s", err)
		// drop
		return nil
	}
	if err := e.processEvents([]byte(req.Body)); err != nil {
		log.Errorf("Failed to process events %s", err)
		return errors.InternalServerError("email.Webhook", "Failed to process events")
	}
	return nil
}

func (e *Email) processEvents(b []byte) error {
	var events []sendgridEvent
	if err := json.Unmarshal(b, &events); err != nil {
		return err
	}
	for _, ev := range events {
		if ev.Event != "blocked" {
			continue
		}
		// lookup and store
		parts := strings.Split(ev.SgMessageId, ".")
		recs, err := store.Read(fmt.Sprintf("%s/%s", prefixSendgridID, parts[0]))
		if err == store.ErrNotFound {
			log.Warnf("Message not found for sendgrid webhook %s", ev.SgMessageId)
			continue
		}
		var s Sent
		if err := json.Unmarshal(recs[0].Value, &s); err != nil {
			log.Errorf("Unable to unmarshal message", err)
			continue
		}
		// TODO do something here to deal with senders with a high block rate
	}
	return nil
}
