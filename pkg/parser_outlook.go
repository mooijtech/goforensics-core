// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"context"
	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/segmentio/kafka-go"
)

func ParseOutlookIMAPEmails(project Project, email string, token string, progressPercentageChannel *chan int) error {
	outlookClient, err := authenticateOutlookIMAP(email, token)

	if err != nil {
		return err
	}

	mailboxes := make(chan *imap.MailboxInfo)
	done := make(chan error)

	go func() {
		done <- outlookClient.List("", "*", mailboxes)
	}()

	var mailboxNames []string

	for m := range mailboxes {
		mailboxNames = append(mailboxNames, m.Name)
	}

	if err := <-done; err != nil {
		return err
	}

	return parseMailboxes(outlookClient, mailboxNames, project, progressPercentageChannel, email, token)
}

func authenticateOutlookIMAP(email string, token string) (*client.Client, error) {
	outlookClient, _ := client.DialTLS("outlook.office365.com:993", nil)
	xoauth2Client := NewXoauth2Client(email, token)

	err := outlookClient.Authenticate(xoauth2Client)

	if err != nil {
		return nil, err
	}

	return outlookClient, nil
}

func parseMailboxes(outlookClient *client.Client, mailboxNames []string, project Project, progressPercentageChannel *chan int, email string, token string) error {
	var parsedMailboxes []string

	for _, mailboxName := range mailboxNames {
		Logger.Infof("Parsing mailbox: %s", mailboxName)

		mbox, err := outlookClient.Select(mailboxName, true)

		if err != nil {
			if err.Error() == "imap: connection closed" {
				Logger.Warnf("IMAP connection closed, retrying...")

				outlookClient, err := authenticateOutlookIMAP(email, token)

				if err != nil {
					return err
				}

				var wantedMailboxes []string

				for _, mailboxName := range mailboxNames {
					containsMailbox := false

					for _, parsedMailbox := range parsedMailboxes {
						if mailboxName == parsedMailbox {
							containsMailbox = true
						}
					}

					if !containsMailbox {
						wantedMailboxes = append(wantedMailboxes, mailboxName)
					}
				}

				err = parseMailboxes(outlookClient, wantedMailboxes, project, progressPercentageChannel, email, token)

				if err != nil {
					return err
				}

				return nil
			}
			return err
		}

		to := mbox.Messages

		seqset := new(imap.SeqSet)
		seqset.AddRange(1, to)

		messages := make(chan *imap.Message)
		done := make(chan error)

		go func() {
			done <- outlookClient.Fetch(seqset, []imap.FetchItem{imap.FetchEnvelope}, messages)
		}()

		var kafkaMessages []kafka.Message

		totalSentMessages := 0

		for imapMessage := range messages {
			message := parseIMAPMessage(imapMessage, project)

			kafkaMessages = append(kafkaMessages, kafka.Message{
				Key:   []byte(message.UUID),
				Value: []byte(message.JSON()),
			})

			if len(kafkaMessages) >= 100 {
				totalSentMessages += len(kafkaMessages)

				err := KafkaWriter.WriteMessages(context.Background(), kafkaMessages...)

				if err != nil {
					return err
				}

				*progressPercentageChannel <- int((float64(totalSentMessages) / float64(mbox.Messages)) * float64(100))

				kafkaMessages = []kafka.Message{}
			}
		}

		if len(kafkaMessages) > 0 {
			err := KafkaWriter.WriteMessages(context.Background(), kafkaMessages...)

			if err != nil {
				return err
			}

			*progressPercentageChannel <- 100
		}

		if err := <-done; err != nil {
			if err.Error() == "The specified message set is invalid." {
				Logger.Warnf("Skipping mailbox %s: %s", mailboxName, err)
				parsedMailboxes = append(parsedMailboxes, mailboxName)
				continue
			}
			return err
		}

		parsedMailboxes = append(parsedMailboxes, mailboxName)
	}

	close(*progressPercentageChannel)

	return outlookClient.Logout()
}

func parseIMAPMessage(message *imap.Message, project Project) Message {
	return Message{
		UUID:        NewUUID(),
		ProjectUUID: project.UUID,
		MessageID:   message.Envelope.MessageId,
		Subject:     message.Envelope.Subject,
		From:        parseAddress(message.Envelope.From),
		To:          parseAddress(message.Envelope.To),
		CC:          parseAddress(message.Envelope.Cc),
		Received:    int(message.Envelope.Date.Unix()),
	}
}

func parseAddress(addresses []*imap.Address) string {
	var from string

	for i, address := range addresses {
		from += address.Address()

		if i != len(addresses) {
			from += ", "
		}
	}

	return from
}
