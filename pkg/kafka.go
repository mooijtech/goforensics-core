// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"github.com/segmentio/kafka-go"
	"github.com/spf13/viper"
)

// KafkaWriter defines our Kafka writer.
var KafkaWriter *kafka.Writer

// init initialize our Kafka writer.
func init() {
	if !viper.IsSet("kafka_address") {
		Logger.Fatal("unset kafka_address configuration variable")
	}
	if !viper.IsSet("kafka_topic") {
		Logger.Fatal("unset kafka_topic configuration variable")
	}

	KafkaWriter = &kafka.Writer{
		Addr:     kafka.TCP(viper.GetString("kafka_address")),
		Topic:    viper.GetString("kafka_topic"),
		Balancer: &kafka.LeastBytes{},
		Async:    true,
		Completion: func(messages []kafka.Message, err error) {
			if err != nil {
				Logger.Errorf("Failed to deliver Kafka message: %s", err)
			}
		},
	}
}