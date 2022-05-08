// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"bytes"
	"encoding/json"
	"github.com/elastic/go-elasticsearch/v7"
	"github.com/spf13/viper"
	"time"
)

// Elasticsearch defines our Elasticsearch client.
var Elasticsearch *elasticsearch.Client

// init initializes our Elasticsearch client.
func init() {
	if !viper.IsSet("elasticsearch_addresses") {
		Logger.Fatal("unset elasticsearch_addresses configuration variable")
	}

	elasticSearch, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses:     viper.GetStringSlice("elasticsearch_addresses"),
		RetryOnStatus: []int{502, 503, 504, 429},
		RetryBackoff: func(i int) time.Duration {
			return time.Duration(i) * 100 * time.Millisecond
		},
		MaxRetries: 5,
	})

	if err != nil {
		Logger.Fatalf("Failed to initialize Elasticsearch client: %s", err)
	}

	Elasticsearch = elasticSearch

	if err := createMessagesIndex(); err != nil {
		Logger.Fatalf("Failed to create message mapping: %s", err)
	}
}

// createMessageMapping creates our Elasticsearch index mapping.
func createMessagesIndex() error {
	if !viper.IsSet("elasticsearch_index") {
		Logger.Fatal("unset elasticsearch_index configuration variable")
	}

	var requestBody bytes.Buffer

	err := json.NewEncoder(&requestBody).Encode(map[string]interface{}{
		"settings": map[string]interface{}{
			"index": map[string]interface{}{
				"number_of_shards":   3,
				"number_of_replicas": 1,
			},
		},
		"mappings": map[string]interface{}{
			"properties": map[string]interface{}{
				"uuid": map[string]interface{}{
					"type": "keyword",
				},
				"project_uuid": map[string]interface{}{
					"type": "keyword",
				},
				"message_id": map[string]interface{}{
					"type": "keyword",
				},
				"subject": map[string]interface{}{
					"type": "text",
				},
				"from": map[string]interface{}{
					"type": "text",
				},
				"to": map[string]interface{}{
					"type": "text",
				},
				"cc": map[string]interface{}{
					"type": "text",
				},
				"received": map[string]interface{}{
					"type": "date",
				},
				"size": map[string]interface{}{
					"type": "text",
				},
				"body": map[string]interface{}{
					"type": "text",
				},
				"headers": map[string]interface{}{
					"type": "text",
				},
				"attachments": map[string]interface{}{
					"properties": map[string]interface{}{
						"uuid": map[string]interface{}{
							"type": "keyword",
						},
						"name": map[string]interface{}{
							"type": "text",
						},
					},
				},
				"folder_uuid": map[string]interface{}{
					"type": "keyword",
				},
				"evidence_uuid": map[string]interface{}{
					"type": "keyword",
				},
			},
		},
	})

	if err != nil {
		return err
	}

	_, err = Elasticsearch.Indices.Create(viper.GetString("elasticsearch_index"), Elasticsearch.Indices.Create.WithBody(&requestBody))

	if err != nil {
		return err
	}

	return nil
}
