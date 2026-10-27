package main

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
)

var metricNames = []string{"allowed", "denied", "denied_ipv4", "denied_ipv6", "denied_protocol", "lookup_error"}

type counterCollector struct {
	values *ebpf.Map
	desc   *prometheus.Desc
	active *prometheus.Desc
}

func newCounterCollector(values *ebpf.Map) *counterCollector {
	return &counterCollector{
		values: values,
		desc:   prometheus.NewDesc("kata_egress_guard_events_total", "eBPF policy decisions", []string{"result"}, nil),
		active: prometheus.NewDesc("kata_egress_guard_attached", "Whether all eBPF links are attached", nil, nil),
	}
}

func (c *counterCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc; ch <- c.active }

func (c *counterCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(c.active, prometheus.GaugeValue, 1)
	for i, name := range metricNames {
		key := uint32(i)
		var perCPU []uint64
		if err := c.values.Lookup(&key, &perCPU); err != nil {
			ch <- prometheus.NewInvalidMetric(c.desc, fmt.Errorf("read counter %s: %w", name, err))
			continue
		}
		var total uint64
		for _, value := range perCPU {
			total += value
		}
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, float64(total), name)
	}
}
