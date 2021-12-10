package handler

import (
	"context"

	"github.com/micro/micro/v3/service/config"
	"github.com/micro/micro/v3/service/logger"
	"github.com/pkg/errors"
	"golang.org/x/text/language"
	"google.golang.org/api/option"

	pb "github.com/micro/services/translate/proto"

	"cloud.google.com/go/translate"
)

type translation struct {
	ApiKey string
}

func NewTranslation() *translation {

	v, err := config.Get("translate.google.api_key")
	if err != nil {
		logger.Fatalf("translate.google.api_key config not found: %v", err)
	}
	key := v.String("")

	if key == "" {
		logger.Fatalf("translate.google.api_key config can not be an empty string")
	}

	return &translation{
		ApiKey: key,
	}
}

// Text calls Google Cloud Translation Basic edition API
// For more information: https://cloud.google.com/translate/docs/samples/translate-text-with-model
func (t *translation) Text(ctx context.Context, req *pb.TextRequest, rsp *pb.TextResponse) error {
	client, err := translate.NewClient(ctx, option.WithAPIKey(t.ApiKey))
	if err != nil {
		return errors.Wrap(err, "new google translation client error")
	}
	defer client.Close()

	source, err := language.Parse(req.Source)
	if err != nil {
		return errors.Wrap(err, "google translation parse source language error")
	}

	target, err := language.Parse(req.Target)
	if err != nil {
		return errors.Wrap(err, "google translation parse target language error")
	}

	result, err := client.Translate(ctx, req.Contents, target, &translate.Options{
		Source: source,
		Format: translate.Format(req.Format),
		Model:  req.Model,
	})

	if err != nil {
		return errors.Wrap(err, "get google translation error")
	}

	for _, v := range result {
		rsp.Translations = append(rsp.Translations, &pb.BasicTranslation{
			Text:   v.Text,
			Source: v.Source.String(),
			Model:  v.Model,
		})
	}

	return nil
}
