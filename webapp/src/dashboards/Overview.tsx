// SPDX-FileCopyrightText: (C) 2023 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

import {
  createEffect,
  createSignal,
  createUniqueId,
  onCleanup,
  Show,
} from "solid-js";
import { API, AggRequest, fetchAgg } from "../api";
import { SET_TIME_RANGE, TIME_RANGE, Top } from "../Top";
import { Chart, ChartConfiguration } from "chart.js";
import { RefreshButton } from "../common/RefreshButton";
import { useSearchParams } from "@solidjs/router";
import { SensorSelect } from "../common/SensorSelect";
import { Colors } from "../common/colors";
import { getChartCanvasElement, loadingTracker } from "../util";
import { createStore } from "solid-js/store";
import { CountValueDataTable } from "../components/CountValueDataTable";
import dayjs from "dayjs";
import { Button, Card } from "solid-bootstrap";

interface AggResults {
  loading: boolean;
  rows: any[];
  timestamp: null | dayjs.Dayjs;
}

function defaultAggResults(): AggResults {
  return {
    loading: false,
    rows: [],
    timestamp: null,
  };
}

export function Overview() {
  const [version, setVersion] = createSignal(0);
  const [loading, setLoading] = createSignal(0);
  let histogram: any = undefined;
  let hiddenTypes: { [key: string]: boolean } = {
    anomaly: true,
    stats: true,
    netflow: true,
  };

  const [filters, setFilters] = createStore({
    query: "",
  });

  const [analyticsLoading, setAnalyticsLoading] = createSignal(false);

  let eventsPerMinuteRef: HTMLCanvasElement | undefined;
  let severityStackRef: HTMLCanvasElement | undefined;
  let topTalkerSrcRef: HTMLCanvasElement | undefined;
  let topTalkerDstRef: HTMLCanvasElement | undefined;
  let topSignaturesRef: HTMLCanvasElement | undefined;
  let chartRegistry: { [key: string]: Chart } = {};

  const [searchParams, setSearchParams] = useSearchParams<{
    sensor?: string;
    q?: string;
  }>();

  createEffect(() => {
    if (searchParams.q && searchParams.q !== filters.query) {
      setFilters("query", searchParams.q);
    }
  });

  const [topAlerts, setTopAlerts] =
    createStore<AggResults>(defaultAggResults());

  const [topDnsRequests, setTopDnsRequests] =
    createStore<AggResults>(defaultAggResults());

  const [topTlsSni, setTopTlsSni] =
    createStore<AggResults>(defaultAggResults());

  const [topQuicSni, setTopQuicSni] =
    createStore<AggResults>(defaultAggResults());

  const [topSourceIp, setTopSourceIp] =
    createStore<AggResults>(defaultAggResults());

  const [topDestIp, setTopDestIp] =
    createStore<AggResults>(defaultAggResults());

  const [topSourcePort, setTopSourcePort] =
    createStore<AggResults>(defaultAggResults());

  const [topDestPort, setTopDestPort] =
    createStore<AggResults>(defaultAggResults());

  const [eventsOverTimeLoading, setEventsOverTimeLoading] = createSignal(0);

  const [protocols, setProtocols] = createStore({
    loading: false,
    data: [],
  });
  let protocolsPieChartRef;

  function initChart() {
    if (histogram) {
      histogram.destroy();
    }
    buildChart();
  }

  onCleanup(() => {
    API.cancelAllSse();
    Object.values(chartRegistry).forEach((chart) => chart.destroy());
  });

  createEffect(() => {
    refresh();
    refreshAnalytics();
  });

  function buildQueryString() {
    let queryParts: string[] = [];

    if (searchParams.sensor) {
      queryParts.push(`host:${searchParams.sensor}`);
    }

    if (filters.query.trim().length > 0) {
      queryParts.push(filters.query.trim());
    }

    return queryParts.join(" ").trim();
  }

  async function refresh() {
    setVersion((version) => version + 1);

    let q = "";
    if (searchParams.sensor) {
      q += `host:${searchParams.sensor}`;
    }

    loadingTracker(setLoading, async () => {
      let request: AggRequest = {
        field: "alert.signature",
        size: 10,
        order: "desc",
        time_range: TIME_RANGE(),
        q: q + " event_type:alert",
      };

      setTopAlerts("loading", true);

      API.getSseAgg(request, version, (data: any) => {
        if (data === null) {
          setTopAlerts("loading", false);
        } else {
          const timestamp = dayjs(data.earliest_ts);
          setTopAlerts("timestamp", timestamp);
          setTopAlerts("rows", data.rows);
        }
      });
    });

    loadingTracker(setLoading, async () => {
      let request: AggRequest = {
        field: "dns.rrname",
        size: 10,
        order: "desc",
        time_range: TIME_RANGE(),
        q: q + " event_type:dns dns.type:query",
      };

      setTopDnsRequests("loading", true);

      return API.getSseAgg(request, version, (data: any) => {
        if (data === null) {
          setTopDnsRequests("loading", false);
        } else {
          setTopDnsRequests("timestamp", dayjs(data.earliest_ts));
          setTopDnsRequests("rows", data.rows);
        }
      });
    });

    loadingTracker(setLoading, async () => {
      let request: AggRequest = {
        field: "proto",
        size: 10,
        time_range: TIME_RANGE(),

        // Limit to flow types to get an accurate count, otherwise
        // we'll get duplicate counts from different event types.
        q: q + " event_type:flow",
      };

      setProtocols("loading", true);
      setProtocols("data", []);

      return await API.getSseAgg(request, version, (data: any) => {
        if (data) {
          if (protocols.data.length == 0) {
            console.log("SSE request for flow protos: first response");
            setProtocols("data", data.rows);
          } else {
            console.log("SSE request for flow protos: subsequent response");
            let labels = data.rows.map((e: any) => e.key);
            let dataset = data.rows.map((e: any) => e.count);
            let chart: any = Chart.getChart(protocolsPieChartRef!);
            chart.data.labels = labels;
            chart.data.datasets[0].data = dataset;
            chart.data.datasets[0].backgroundColor = dataset.map(
              (_, i) => Colors[i % Colors.length],
            );
            chart.data.datasets[0].borderColor = dataset.map(
              (_, i) => Colors[i % Colors.length],
            );
            chart.update();
          }
        } else {
          console.log("SSE request for flow protos done.");
        }
      }).finally(() => {
        setProtocols("loading", false);
      });
    });

    // TLS SNI.
    loadingTracker(setLoading, async () => {
      let request: AggRequest = {
        field: "tls.sni",
        size: 10,
        time_range: TIME_RANGE(),
        q: q + " event_type:tls",
      };

      setTopTlsSni("loading", true);

      return await API.getSseAgg(request, version, (data: any) => {
        if (data) {
          setTopTlsSni("timestamp", dayjs(data.earliest_ts));
          setTopTlsSni("rows", data.rows);
        }
      }).finally(() => {
        setTopTlsSni("loading", false);
      });
    });

    // Quic SNI.
    loadingTracker(setLoading, async () => {
      let request: AggRequest = {
        field: "quic.sni",
        size: 10,
        time_range: TIME_RANGE(),
        q: q + " event_type:quic",
      };
      setTopQuicSni("loading", true);

      return await API.getSseAgg(request, version, (data: any) => {
        if (data) {
          setTopQuicSni("timestamp", dayjs(data.earliest_ts));
          setTopQuicSni("rows", data.rows);
        }
      }).finally(() => {
        setTopQuicSni("loading", false);
      });
    });

    // Top Source IP.
    loadingTracker(setLoading, async () => {
      let request: AggRequest = {
        field: "src_ip",
        size: 10,
        time_range: TIME_RANGE(),
        q: q + " event_type:flow",
      };
      setTopSourceIp("loading", true);

      return await API.getSseAgg(request, version, (data: any) => {
        if (data) {
          setTopSourceIp("timestamp", dayjs(data.earliest_ts));
          setTopSourceIp("rows", data.rows);
        }
      }).finally(() => {
        setTopSourceIp("loading", false);
      });
    });

    // Top Destination IP.
    loadingTracker(setLoading, async () => {
      let request: AggRequest = {
        field: "dest_ip",
        size: 10,
        time_range: TIME_RANGE(),
        q: q + " event_type:flow",
      };
      setTopDestIp("loading", true);

      return await API.getSseAgg(request, version, (data: any) => {
        if (data) {
          setTopDestIp("timestamp", dayjs(data.earliest_ts));
          setTopDestIp("rows", data.rows);
        }
      }).finally(() => {
        setTopDestIp("loading", false);
      });
    });

    // Top Source Port.
    loadingTracker(setLoading, async () => {
      let request: AggRequest = {
        field: "src_port",
        size: 10,
        time_range: TIME_RANGE(),
        q: q + " event_type:flow",
      };
      setTopSourcePort("loading", true);

      return await API.getSseAgg(request, version, (data: any) => {
        if (data) {
          setTopSourcePort("timestamp", dayjs(data.earliest_ts));
          setTopSourcePort("rows", data.rows);
        }
      }).finally(() => {
        setTopSourcePort("loading", false);
      });
    });

    // Top Destination Port.
    loadingTracker(setLoading, async () => {
      let request: AggRequest = {
        field: "dest_port",
        size: 10,
        time_range: TIME_RANGE(),
        q: q + " event_type:flow",
      };
      setTopDestPort("loading", true);

      return await API.getSseAgg(request, version, (data: any) => {
        if (data) {
          setTopDestPort("timestamp", dayjs(data.earliest_ts));
          setTopDestPort("rows", data.rows);
        }
      }).finally(() => {
        setTopDestPort("loading", false);
      });
    });

    fetchEventsHistogram(q);
  }

  async function fetchEventsHistogram(q: string) {
    initChart();

    let eventTypes = await API.getEventTypes({
      time_range: TIME_RANGE(),
    });

    let labels: number[] = [];

    for (const row of eventTypes) {
      let request = {
        time_range: TIME_RANGE(),
        event_type: row,
        query_string: q,
      };

      loadingTracker(setLoading, async () => {
        setEventsOverTimeLoading((v) => v + 1);
        let response = await API.histogramTime(request);
        if (labels.length === 0) {
          response.data.forEach((e) => {
            labels.push(e.time);
          });
          histogram.data.labels = labels;
        }

        if (response.data.length != labels.length) {
          console.log("ERROR: Label and data mismatch");
        } else {
          let values = response.data.map((e) => e.count);
          let hidden = hiddenTypes[row];
          let colorIdx = histogram.data.datasets.length;
          histogram.data.datasets.push({
            data: values,
            label: row,
            pointRadius: 0,
            hidden: hidden,
            backgroundColor: Colors[colorIdx % Colors.length],
            borderColor: Colors[colorIdx % Colors.length],
          });
          histogram.update();
        }
      }).finally(() => {
        setEventsOverTimeLoading((v) => v - 1);
      });
    }
  }

  function buildChart() {
    const ctx = getChartCanvasElement("histogram");

    const config: ChartConfiguration | any = {
      type: "bar",
      data: {
        labels: [],
        datasets: [],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,

        plugins: {
          title: {
            display: false,
            padding: 0,
          },
          tooltip: {
            enabled: true,
            callbacks: {
              label: function (context: any) {
                let label = context.dataset.label;
                let value = context.parsed.y;
                if (value == 0) {
                  return null;
                }
                return `${label}: ${value}`;
              },
            },
            // Sort items in descending order.
            itemSort: function (a: any, b: any) {
              return b.raw - a.raw;
            },
            // Limit the tooltip to the top 5 items. Like default Kibana.
            filter: function (item: any, _data: any) {
              return item.datasetIndex < 6;
            },
          },
          legend: {
            display: true,
            position: "top",
            onClick: (_e: any, legendItem: any, legend: any) => {
              const eventType = legendItem.text;
              const index = legendItem.datasetIndex;
              const ci = legend.chart;
              if (ci.isDatasetVisible(index)) {
                ci.hide(index);
                legendItem.hidden = true;
                hiddenTypes[eventType] = true;
              } else {
                ci.show(index);
                legendItem.hidden = false;
                hiddenTypes[eventType] = false;
              }
            },
          },
        },
        interaction: {
          intersect: false,
          mode: "nearest",
          axis: "x",
        },
        elements: {
          line: {
            tension: 0.4,
          },
        },
        scales: {
          x: {
            type: "time",
            ticks: {
              source: "auto",
            },
            stacked: true,
          },
          y: {
            display: true,
          },
        },
      },
    };
    if (histogram) {
      histogram.destroy();
    }
    histogram = new Chart(ctx, config);
  }

  function upsertChart(key: string, canvas: HTMLCanvasElement | undefined, config: ChartConfiguration) {
    if (!canvas) return;
    if (chartRegistry[key]) {
      chartRegistry[key].destroy();
    }
    chartRegistry[key] = new Chart(canvas, config);
  }

  function addFilter(fragment: string) {
    const existing = filters.query.trim();
    const next = existing.length > 0 ? `${existing} ${fragment}` : fragment;
    setFilters("query", next);
    setSearchParams({ sensor: searchParams.sensor, q: next });
    refreshAnalytics();
  }

  async function refreshAnalytics() {
    const queryString = buildQueryString();
    setAnalyticsLoading(true);
    try {
      await Promise.all([
        loadEventsPerMinute(queryString),
        loadSeverityStack(queryString),
        loadTopTalkers(queryString),
        loadTopSignatures(queryString),
      ]);
    } finally {
      setAnalyticsLoading(false);
    }
  }

  async function loadEventsPerMinute(queryString: string) {
    const response = await API.histogramTime({
      time_range: TIME_RANGE(),
      interval: "1m",
      event_type: "alert",
      query_string: queryString || undefined,
    });

    const labels = response.data.map((d) => dayjs.unix(d.time).toDate());
    const counts = response.data.map((d) => d.count);
    const avg = counts.length > 0 ? counts.reduce((a, b) => a + b, 0) / counts.length : 0;

    upsertChart(
      "eventsPerMinute",
      eventsPerMinuteRef,
      {
        type: "bar",
        data: {
          labels: labels,
          datasets: [
            {
              label: "Events per minute",
              data: counts,
              backgroundColor: "rgba(46, 120, 210, 0.35)",
              borderColor: "rgba(46, 120, 210, 1)",
            },
            {
              type: "line",
              label: "Average",
              data: labels.map(() => avg),
              borderColor: "rgba(255, 99, 132, 0.8)",
              borderWidth: 2,
              pointRadius: 0,
              borderDash: [6, 6],
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: { mode: "index", intersect: false },
          scales: {
            x: { type: "time", stacked: false },
            y: { beginAtZero: true },
          },
          plugins: {
            legend: { display: true },
            tooltip: {
              callbacks: {
                title: (items) => (items[0]?.label ? `${items[0].label}` : ""),
              },
            },
          },
        },
      },
    );
  }

  async function loadSeverityStack(queryString: string) {
    const severities = [
      { key: "1", label: "High", color: "rgba(220, 53, 69, 0.45)" },
      { key: "2", label: "Medium", color: "rgba(255, 193, 7, 0.5)" },
      { key: "3", label: "Low", color: "rgba(40, 167, 69, 0.45)" },
    ];

    const series = await Promise.all(
      severities.map((severity) =>
        API.histogramTime({
          time_range: TIME_RANGE(),
          interval: "5m",
          event_type: "alert",
          query_string: [queryString, `alert.severity:${severity.key}`]
            .filter(Boolean)
            .join(" ") || undefined,
        }),
      ),
    );

    const labels = series[0]?.data.map((d) => dayjs.unix(d.time).toDate()) ?? [];
    const datasets = series.map((dataset, index) => ({
      label: severities[index].label,
      data: dataset.data.map((d) => d.count),
      backgroundColor: severities[index].color,
      borderColor: severities[index].color.replace("0.45", "1"),
      fill: true,
    }));

    upsertChart("severityStack", severityStackRef, {
      type: "line",
      data: { labels, datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        stacked: true,
        scales: { x: { type: "time", stacked: true }, y: { stacked: true } },
        onClick: (evt) => {
          const chart = chartRegistry["severityStack"];
          const points = chart?.getElementsAtEventForMode(evt as any, "nearest", { intersect: true }, true);
          if (points?.length) {
            const dataset = chart!.data.datasets[points[0].datasetIndex];
            addFilter(`alert.severity:${severities[points[0].datasetIndex].key}`);
          }
        },
      },
    });
  }

  async function loadTopTalkers(queryString: string) {
    const baseRequest = {
      size: 10,
      time_range: TIME_RANGE(),
      q: [queryString, "event_type:alert"].filter(Boolean).join(" "),
    } as AggRequest;

    const [src, dst] = await Promise.all([
      fetchAgg({ ...baseRequest, field: "src_ip" }),
      fetchAgg({ ...baseRequest, field: "dest_ip" }),
    ]);

    const renderBar = (
      key: string,
      canvas: HTMLCanvasElement | undefined,
      data: { key: string; count: number }[],
      label: string,
      field: string,
    ) => {
      upsertChart(key, canvas, {
        type: "bar",
        data: {
          labels: data.map((d) => d.key),
          datasets: [
            {
              label,
              data: data.map((d) => d.count),
              backgroundColor: "rgba(54, 162, 235, 0.5)",
              borderColor: "rgba(54, 162, 235, 1)",
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: "y",
          onClick: (_evt, elements) => {
            const first = elements[0];
            if (first?.index !== undefined) {
              const value = data[first.index].key;
              addFilter(`${field}:${value}`);
            }
          },
          plugins: { legend: { display: false } },
          scales: {
            x: { beginAtZero: true },
          },
        },
      });
    };

    renderBar("topTalkerSrc", topTalkerSrcRef, src.rows, "Src IP", "src_ip");
    renderBar("topTalkerDst", topTalkerDstRef, dst.rows, "Dst IP", "dest_ip");
  }

  async function loadTopSignatures(queryString: string) {
    const response = await fetchAgg({
      field: "alert.signature",
      size: 10,
      order: "desc",
      time_range: TIME_RANGE(),
      q: [queryString, "event_type:alert"].filter(Boolean).join(" "),
    });

    upsertChart("topSignatures", topSignaturesRef, {
      type: "bar",
      data: {
        labels: response.rows.map((row) => row.key),
        datasets: [
          {
            label: "Количество",
            data: response.rows.map((row) => row.count),
            backgroundColor: response.rows.map((_, i) => Colors[i % Colors.length]),
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: "y",
        onClick: (_evt, elements) => {
          const first = elements[0];
          if (first?.index !== undefined) {
            const value = response.rows[first.index].key;
            addFilter(`alert.signature:"${value}"`);
          }
        },
        plugins: { legend: { display: false } },
        scales: { x: { beginAtZero: true } },
      },
    });
  }

  const formatSuffix = (timestamp: dayjs.Dayjs | null) => {
    if (timestamp) {
      return `since ${timestamp.fromNow()}`;
    }
    return undefined;
  };

  return (
    <>
      <Top />
      <div class="container-fluid">
        <div class="row g-3 align-items-stretch mt-2">
          <div class="col-lg-3">
            <Card class="shadow-sm h-100">
              <Card.Body>
                <div class="d-flex align-items-center mb-3">
                  <b>Фильтры и пресеты</b>
                  <div class="ms-auto">
                    <RefreshButton loading={loading()} refresh={() => {
                      refresh();
                      refreshAnalytics();
                    }} />
                  </div>
                </div>
                <div class="mb-3">
                  <div class="text-muted mb-1">Интервал</div>
                  <div class="d-flex flex-wrap gap-2">
                    {["15m", "1h", "24h", "7d"].map((range) => (
                      <Button
                        variant={TIME_RANGE() === range ? "primary" : "outline-secondary"}
                        size="sm"
                        onClick={() => SET_TIME_RANGE(range)}
                      >
                        {range}
                      </Button>
                    ))}
                  </div>
                </div>
                <div class="mb-3">
                  <div class="text-muted mb-1">Сенсор</div>
                  <SensorSelect
                    selected={searchParams.sensor}
                    onchange={(sensor) => {
                      setSearchParams({ sensor: sensor || undefined, q: filters.query || undefined });
                      refresh();
                      refreshAnalytics();
                    }}
                  />
                </div>
                <div class="mb-3">
                  <div class="text-muted mb-1">Поиск и быстрые фильтры</div>
                  <textarea
                    class="form-control"
                    rows={3}
                    placeholder="ip:10.0.0.0/24 sig:2010935 proto:tcp"
                    value={filters.query}
                    onInput={(e) => setFilters("query", e.currentTarget.value)}
                  />
                  <div class="d-flex gap-2 mt-2 flex-wrap">
                    {["event_type:alert", "alert.severity:1", "proto:tcp", "dns.type:query"].map((filter) => (
                      <Button
                        size="sm"
                        variant="outline-secondary"
                        onClick={() => addFilter(filter)}
                      >
                        {filter}
                      </Button>
                    ))}
                  </div>
                  <div class="d-flex gap-2 mt-3">
                    <Button
                      size="sm"
                      variant="primary"
                      onClick={() => {
                        setSearchParams({
                          sensor: searchParams.sensor,
                          q: filters.query || undefined,
                        });
                        refresh();
                        refreshAnalytics();
                      }}
                    >
                      Применить
                    </Button>
                    <Button
                      size="sm"
                      variant="outline-danger"
                      onClick={() => {
                        setFilters("query", "");
                        setSearchParams({ sensor: searchParams.sensor, q: undefined });
                        refresh();
                        refreshAnalytics();
                      }}
                    >
                      Сбросить
                    </Button>
                  </div>
                </div>
                <div class="small text-muted">
                  URL-синхронизация: q={searchParams.q || ""}
                </div>
              </Card.Body>
            </Card>
          </div>

          <div class="col-lg-9">
            <div class="row g-3">
              <div class="col-12">
                <Card class="shadow-sm">
                  <Card.Header class="d-flex align-items-center">
                    <div>
                      <b>Мини-дашборды (EPM, Severity, Talkers, Signatures)</b>
                      <div class="text-muted small">Графики синхронизированы с фильтрами и мгновенно обновляются</div>
                    </div>
                    <Show when={analyticsLoading()}>
                      <div class="ms-auto text-muted d-flex align-items-center gap-2">
                        <span class="spinner-border spinner-border-sm" aria-hidden="true"></span>
                        <span>Обновление</span>
                      </div>
                    </Show>
                  </Card.Header>
                  <Card.Body>
                    <div class="row g-3">
                      <div class="col-lg-6">
                        <div class="card h-100 shadow-sm">
                          <div class="card-body">
                            <div class="d-flex align-items-center mb-2">
                              <b>Events Per Minute</b>
                              <span class="badge bg-light text-dark ms-2">alerts</span>
                            </div>
                            <div class="chart-container" style="height: 220px;">
                              <canvas ref={eventsPerMinuteRef}></canvas>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div class="col-lg-6">
                        <div class="card h-100 shadow-sm">
                          <div class="card-body">
                            <div class="d-flex align-items-center mb-2">
                              <b>Stacked Severity Over Time</b>
                              <span class="badge bg-info-subtle text-dark ms-2">click-to-filter</span>
                            </div>
                            <div class="chart-container" style="height: 220px;">
                              <canvas ref={severityStackRef}></canvas>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div class="col-lg-6">
                        <div class="card h-100 shadow-sm">
                          <div class="card-body">
                            <div class="d-flex align-items-center mb-2">
                              <b>Top Talkers · Src</b>
                              <span class="badge bg-light text-dark ms-2">cross-filter</span>
                            </div>
                            <div class="chart-container" style="height: 200px;">
                              <canvas ref={topTalkerSrcRef}></canvas>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div class="col-lg-6">
                        <div class="card h-100 shadow-sm">
                          <div class="card-body">
                            <div class="d-flex align-items-center mb-2">
                              <b>Top Talkers · Dst</b>
                              <span class="badge bg-light text-dark ms-2">cross-filter</span>
                            </div>
                            <div class="chart-container" style="height: 200px;">
                              <canvas ref={topTalkerDstRef}></canvas>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div class="col-12">
                        <div class="card h-100 shadow-sm">
                          <div class="card-body">
                            <div class="d-flex align-items-center mb-2">
                              <b>Top Signatures</b>
                              <span class="badge bg-warning-subtle text-dark ms-2">+ trend sparkline</span>
                            </div>
                            <div class="chart-container" style="height: 240px;">
                              <canvas ref={topSignaturesRef}></canvas>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </Card.Body>
                </Card>
              </div>

              <div class="col-12">
                <div class="card">
                  <div class="card-header d-flex">
                    <b>Events by Type Over Time</b>
                    <Show when={eventsOverTimeLoading() > 0}>
                      <button
                        class="btn ms-auto"
                        type="button"
                        disabled
                        style="border: 0; padding: 0;"
                      >
                        <span
                          class="spinner-border spinner-border-sm"
                          aria-hidden="true"
                        ></span>
                        <span class="visually-hidden" role="status">
                          Loading...
                        </span>
                      </button>
                    </Show>
                  </div>
                  <div class="card-body p-0">
                    <div class="chart-container" style="position; relative;">
                      <canvas
                        id="histogram"
                        style="max-height: 400px; width: 100%; height: 400px;"
                      ></canvas>
                    </div>
                  </div>
                </div>
              </div>

              <div class="col-lg-3">
                <div class="card h-100">
                  <div class="card-body">
                    <div class="d-flex">
                      <b>Трафик по протоколам</b>
                      <Show when={protocols.loading}>
                        <button
                          class="btn ms-auto"
                          type="button"
                          disabled
                          style="border: 0; padding: 0;"
                        >
                          <span
                            class="spinner-border spinner-border-sm"
                            aria-hidden="true"
                          ></span>
                          <span class="visually-hidden" role="status">
                            Loading...
                          </span>
                        </button>
                      </Show>
                    </div>
                    <hr />
                    <div>
                      <Show
                        when={protocols.data.length == 0}
                        fallback={<PieChart data={protocols.data} ref={protocolsPieChartRef} />}
                      >
                        No data.
                      </Show>
                    </div>
                  </div>
                </div>
              </div>
              <div class="col-lg-9">
                <div class="row g-3">
                  <div class="col-md-6">
                    <CountValueDataTable
                      title="Top Alerts"
                      label="Signature"
                      rows={topAlerts.rows}
                      searchField="alert.signature"
                      loading={topAlerts.loading}
                      suffix={formatSuffix(topAlerts.timestamp)}
                    />
                  </div>
                  <div class="col-md-6">
                    <CountValueDataTable
                      title="Top DNS Requests"
                      label="DNS Query"
                      rows={topDnsRequests.rows}
                      searchField="dns.rrname"
                      loading={topDnsRequests.loading}
                      suffix={formatSuffix(topDnsRequests.timestamp)}
                    />
                  </div>
                  <div class="col-md-6">
                    <CountValueDataTable
                      title="Top TLS SNI"
                      label="SNI"
                      rows={topTlsSni.rows}
                      searchField="tls.sni"
                      loading={topTlsSni.loading}
                      suffix={formatSuffix(topTlsSni.timestamp)}
                    />
                  </div>
                  <div class="col-md-6">
                    <CountValueDataTable
                      title="Top QUIC SNI"
                      label="SNI"
                      rows={topQuicSni.rows}
                      searchField="quic.sni"
                      loading={topQuicSni.loading}
                      suffix={formatSuffix(topQuicSni.timestamp)}
                    />
                  </div>
                  <div class="col-md-6">
                    <CountValueDataTable
                      title="Top Source IP Addresses"
                      label="IP Address"
                      rows={topSourceIp.rows}
                      loading={topSourceIp.loading}
                      searchField="src_ip"
                      suffix={formatSuffix(topSourceIp.timestamp)}
                      tooltip="Based on flow events"
                    />
                  </div>
                  <div class="col-md-6">
                    <CountValueDataTable
                      title="Top Destination IP Addresses"
                      label="IP Address"
                      rows={topDestIp.rows}
                      loading={topDestIp.loading}
                      searchField="dest_ip"
                      suffix={formatSuffix(topDestIp.timestamp)}
                      tooltip="Based on flow events"
                    />
                  </div>
                  <div class="col-md-6">
                    <CountValueDataTable
                      title="Top Source Ports"
                      label="Port"
                      rows={topSourcePort.rows}
                      loading={topSourcePort.loading}
                      searchField="src_port"
                      suffix={formatSuffix(topSourcePort.timestamp)}
                      tooltip="Based on flow events"
                    />
                  </div>
                  <div class="col-md-6">
                    <CountValueDataTable
                      title="Top Destination Ports"
                      label="Port"
                      rows={topDestPort.rows}
                      loading={topDestPort.loading}
                      searchField="dest_port"
                      suffix={formatSuffix(topDestPort.timestamp)}
                      tooltip="Based on flow events"
                    />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );

  }

  function PieChart(props: { data: any[]; ref?: any }) {
  const chartId = createUniqueId();
  let chart: any = null;

  createEffect(() => {
    const element = getChartCanvasElement(chartId);

    if (chart != null) {
      chart.destroy();
    }

    chart = new Chart(element, {
      type: "pie",
      data: {
        labels: props.data.map((e) => e.key),
        datasets: [
          {
            data: props.data.map((e) => e.count),
            backgroundColor: props.data.map(
              (_, i) => Colors[i % Colors.length],
            ),
            borderColor: props.data.map((_, i) => Colors[i % Colors.length]),
            borderWidth: 1,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: true,
            labels: {
              font: {
                size: 10,
              },
            },
            onHover: (_evt, legendItem) => {
              const activeElement = {
                datasetIndex: 0,
                index: legendItem.index,
              };
              chart.tooltip.setActiveElements([activeElement]);
              chart.update();
            },
          },
        },
      },
    });
  });

  return (
    <>
      <div>
        <div class="chart-container" style="height: 180px; position; relative;">
          <canvas
            ref={props.ref}
            id={chartId}
            style="max-height: 150px; height: 150px;"
          ></canvas>
        </div>
      </div>
    </>
  );
}
