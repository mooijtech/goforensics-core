// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import "github.com/segmentio/kafka-go"

// KafkaWriter defines our Kafka writer.
var KafkaWriter = &kafka.Writer{
	Addr:     kafka.TCP("localhost:9092"),
	Topic:    "messages",
	Balancer: &kafka.LeastBytes{},
	Async:    true,
	Completion: func(messages []kafka.Message, err error) {
		if err != nil {
			Logger.Errorf("Kafka failed to deliver message: %s", err)
		}
	},
}
