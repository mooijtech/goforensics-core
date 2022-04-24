<h1 align="center">
  <br>
  <a href="https://github.com/mooijtech/goforensics-core"><img src="https://i.imgur.com/kd7fwOf.png" alt="Go Forensics Core" width="180"></a>
  <br>
  Go Forensics Core
  <br>
</h1>

<h4 align="center">Open source forensic software to analyze digital evidence to be presented in court.</h4>

---

The core of [Go Forensics](https://www.goforensics.io/)

### Kafka

The core sends all messages to [Kafka](https://kafka.apache.org/).

```bash
$ cd ~/path/to/kafka/
$ ./bin/zookeeper-server-start.sh config/zookeeper.properties
$ ./bin/kafka-server-start.sh config/server.properties
```

### Vector

[Vector](https://vector.dev/) is used to process messages from Kafka to Elasticsearch.

```bash
$ vector --config vector.toml
```

### Elasticsearch

The core searches all messages via [Elasticsearch](https://www.elastic.co/elasticsearch/).

```bash
# Change directory
$ cd ~/path/to/elasticsearch

# Start Elasticsearch
$ ./bin/elasticsearch
```

### Libraries

- [logrus](https://github.com/sirupsen/logrus)
- [go-sqlite3](https://github.com/mattn/go-sqlite3)
- [bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt)
- [ksuid](https://github.com/segmentio/ksuid)
- [go-elasticsearch](https://github.com/elastic/go-elasticsearch)
- [kafka-go](https://github.com/segmentio/kafka-go)
- [go-pst](https://github.com/mooijtech/go-pst)
- [go-message](https://github.com/emersion/go-message)
- [errgroup](https://pkg.go.dev/golang.org/x/sync/errgroup)
- [minio](https://github.com/minio/minio-go)
- [postmark-go](https://github.com/mattevans/postmark-go)
- [kratos-client-go](https://github.com/ory/kratos-client-go)
- [go-sasl](https://github.com/emersion/go-sasl)