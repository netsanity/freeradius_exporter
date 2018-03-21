package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/ThoreKr/radius"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	up = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_up",
			Help: "Value whether a connection to FreeRadius has been successful",
		})

	totalAccessRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_access_requests",
			Help: "Add some useful helptext here",
		})

	totalAccessAccepts = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_access_accepts",
			Help: "Add some useful helptext here",
		})

	totalAccessRejects = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_access_rejects",
			Help: "Add some useful helptext here",
		})

	totalAccessChallenges = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_access_challenges",
			Help: "Add some useful helptext here",
		})

	totalAuthResponses = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_auth_responses",
			Help: "Add some useful helptext here",
		})

	totalAuthDuplicateRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_auth_duplicate_requests",
			Help: "Add some useful helptext here",
		})

	totalAuthMalformedRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_auth_malformed_requests",
			Help: "Add some useful helptext here",
		})

	totalAuthInvalidRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_auth_invalid_requests",
			Help: "Add some useful helptext here",
		})

	totalAuthDroppedRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_auth_dropped_requests",
			Help: "Add some useful helptext here",
		})

	totalAuthUnknownTypes = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_auth_unknown_types",
			Help: "Add some useful helptext here",
		})

	totalAccountingRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_accounting_requests",
			Help: "Add some useful helptext here",
		})

	totalAccountingResponses = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_accounting_responses",
			Help: "Add some useful helptext here",
		})

	totalAcctDuplicateRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_acct_duplicate_requests",
			Help: "Add some useful helptext here",
		})

	totalAcctMalformedRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_acct_malformed_requests",
			Help: "Add some useful helptext here",
		})

	totalAcctInvalidRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_acct_invalid_requests",
			Help: "Add some useful helptext here",
		})

	totalAcctDroppedRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_acct_dropped_requests",
			Help: "Add some useful helptext here",
		})

	totalAcctUnknownTypes = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_acct_unknown_types",
			Help: "Add some useful helptext here",
		})

	totalProxyAccessRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_proxy_access_requests",
			Help: "Add some useful helptext here",
		})

	totalProxyAccessAccepts = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_proxy_access_accepts",
			Help: "Add some useful helptext here",
		})

	totalProxyAccessRejects = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_proxy_access_rejects",
			Help: "Add some useful helptext here",
		})

	totalProxyAccessChallenges = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_proxy_access_challenges",
			Help: "Add some useful helptext here",
		})

	totalProxyAuthResponses = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_proxy_auth_responses",
			Help: "Add some useful helptext here",
		})

	totalProxyAuthDuplicateRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_proxy_auth_duplicate_requests",
			Help: "Add some useful helptext here",
		})

	totalProxyAuthMalformedRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_proxy_auth_malformed_requests",
			Help: "Add some useful helptext here",
		})

	totalProxyAuthInvalidRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_proxy_auth_invalid_requests",
			Help: "Add some useful helptext here",
		})

	totalProxyAuthDroppedRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_proxy_auth_dropped_requests",
			Help: "Add some useful helptext here",
		})

	totalProxyAuthUnknownTypes = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_proxy_auth_unknown_types",
			Help: "Add some useful helptext here",
		})

	totalProxyAccountingRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_proxy_accounting_requests",
			Help: "Add some useful helptext here",
		})

	totalProxyAccountingResponses = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_proxy_accounting_responses",
			Help: "Add some useful helptext here",
		})

	totalProxyAcctDuplicateRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_proxy_acct_duplicate_requests",
			Help: "Add some useful helptext here",
		})

	totalProxyAcctMalformedRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_proxy_acct_malformed_requests",
			Help: "Add some useful helptext here",
		})

	totalProxyAcctInvalidRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_proxy_acct_invalid_requests",
			Help: "Add some useful helptext here",
		})

	totalProxyAcctDroppedRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_proxy_acct_dropped_requests",
			Help: "Add some useful helptext here",
		})

	totalProxyAcctUnknownTypes = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_total_proxy_acct_unknown_types",
			Help: "Add some useful helptext here",
		})

	statsStartTime = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_stats_start_time",
			Help: "Add some useful helptext here",
		})

	statsHUPTime = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_stats_hup_time",
			Help: "Add some useful helptext here",
		})

	queueLenInternal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_queue_len_internal",
			Help: "Add some useful helptext here",
		})

	queueLenProxy = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_queue_len_proxy",
			Help: "Add some useful helptext here",
		})

	queueLenAuth = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_queue_len_auth",
			Help: "Add some useful helptext here",
		})

	queueLenAcct = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_queue_len_acct",
			Help: "Add some useful helptext here",
		})

	queueLenDetail = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_queue_len_detail",
			Help: "Add some useful helptext here",
		})

	queuePPSIn = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_queue_pps_in",
			Help: "Add some useful helptext here",
		})

	queuePPSOut = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "freeradius_queue_pps_out",
			Help: "Add some useful helptext here",
		})
)

const (
	Message_Authenticator      radius.Type = 0
	FreeRADIUS_Statistics_Type radius.Type = 31
)

func init() {
	// Register metrics
	prometheus.MustRegister(up)
	prometheus.MustRegister(totalAccessRequests)
	prometheus.MustRegister(totalAccessAccepts)
	prometheus.MustRegister(totalAccessRejects)
	prometheus.MustRegister(totalAccessChallenges)
	prometheus.MustRegister(totalAuthResponses)
	prometheus.MustRegister(totalAuthDuplicateRequests)
	prometheus.MustRegister(totalAuthMalformedRequests)
	prometheus.MustRegister(totalAuthInvalidRequests)
	prometheus.MustRegister(totalAuthDroppedRequests)
	prometheus.MustRegister(totalAuthUnknownTypes)
	prometheus.MustRegister(totalAccountingRequests)
	prometheus.MustRegister(totalAccountingResponses)
	prometheus.MustRegister(totalAcctDuplicateRequests)
	prometheus.MustRegister(totalAcctMalformedRequests)
	prometheus.MustRegister(totalAcctInvalidRequests)
	prometheus.MustRegister(totalAcctDroppedRequests)
	prometheus.MustRegister(totalAcctUnknownTypes)
	prometheus.MustRegister(totalProxyAccessRequests)
	prometheus.MustRegister(totalProxyAccessAccepts)
	prometheus.MustRegister(totalProxyAccessRejects)
	prometheus.MustRegister(totalProxyAccessChallenges)
	prometheus.MustRegister(totalProxyAuthResponses)
	prometheus.MustRegister(totalProxyAuthDuplicateRequests)
	prometheus.MustRegister(totalProxyAuthMalformedRequests)
	prometheus.MustRegister(totalProxyAuthInvalidRequests)
	prometheus.MustRegister(totalProxyAuthDroppedRequests)
	prometheus.MustRegister(totalProxyAuthUnknownTypes)
	prometheus.MustRegister(totalProxyAccountingRequests)
	prometheus.MustRegister(totalProxyAccountingResponses)
	prometheus.MustRegister(totalProxyAcctDuplicateRequests)
	prometheus.MustRegister(totalProxyAcctMalformedRequests)
	prometheus.MustRegister(totalProxyAcctInvalidRequests)
	prometheus.MustRegister(totalProxyAcctDroppedRequests)
	prometheus.MustRegister(totalProxyAcctUnknownTypes)
	prometheus.MustRegister(statsStartTime)
	prometheus.MustRegister(statsHUPTime)
	prometheus.MustRegister(queueLenInternal)
	prometheus.MustRegister(queueLenProxy)
	prometheus.MustRegister(queueLenAuth)
	prometheus.MustRegister(queueLenAcct)
	prometheus.MustRegister(queueLenDetail)
	prometheus.MustRegister(queuePPSIn)
	prometheus.MustRegister(queuePPSOut)
}

func main() {
	var (
		addr          = flag.String("telemetry.addr", ":9330", "host:port for syncrepl exporter")
		metricsPath   = flag.String("telemetry.path", "/metrics", "URL path for surfacing collected metrics")
		freeradHost   = flag.String("freerad.host", "localhost:18121", "hostname:port of the FreeRadius server")
		freeradSecret = flag.String("freerad.secret", "adminsecret", "The client secret to query the status server")
	)
	flag.Parse()

	// Message-Authenticator = 0x00, FreeRADIUS-Statistics-Type = 31
	packet := radius.New(radius.CodeStatusServer, []byte(*freeradSecret))
	messageAuthenticator, _ := radius.NewString("Message-Authenticator")
	statisticsType, _ := radius.NewString("FreeRADIUS-Statistics-Type")

	// FreeRADIUS-Statistics-Type = 31 "ALL"
	packet.Set(FreeRADIUS_Statistics_Type, statisticsType)

	// Message-Authenticator = 0x00
	packet.Set(Message_Authenticator, messageAuthenticator)

	fmt.Println(packet)
	response, err := radius.Exchange(context.Background(), packet, *freeradHost)
	if err != nil {
		panic(err)
	}

	if response.Code == radius.CodeAccessAccept {
		fmt.Println("Accepted")
	} else {
		fmt.Println("Denied")
	}

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
			<head><title>FreeRadius Exporter</title></head>
			<body>
			<h1>FreeRadius Exporter</h1>
			<p><a href='` + *metricsPath + `'>Metrics</a></p>
			</body>
			</html>`))
	})

	log.Printf("Starting FreeRadius exporter on %q", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
