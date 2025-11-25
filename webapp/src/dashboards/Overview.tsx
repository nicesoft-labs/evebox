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
import {
  ArcElement,
  BarController,
  BarElement,
  BubbleController,
  CategoryScale,
  Chart,
  ChartConfiguration,
  Legend,
  Filler,
  LineController,
  LineElement,
  LinearScale,
  PointElement,
  ScatterController,
  TimeScale,
  Tooltip,
} from "chart.js";
import "chartjs-adapter-date-fns";
import { RefreshButton } from "../common/RefreshButton";
import { useSearchParams } from "@solidjs/router";
import { SensorSelect } from "../common/SensorSelect";
import { Colors } from "../common/colors";
import { getChartCanvasElement, loadingTracker } from "../util";
import { createStore } from "solid-js/store";
import { CountValueDataTable } from "../components/CountValueDataTable";
import dayjs from "dayjs";
import { Button, Card } from "solid-bootstrap";

Chart.register(
  BarElement,
  BarController,
  LineElement,
  LineController,
  PointElement,
  ArcElement,
  BubbleController,
  ScatterController,
  CategoryScale,
  LinearScale,
  TimeScale,
  Tooltip,
  Legend,
  Filler,
);

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
  let histogram: Chart | undefined;
  let hiddenTypes: { [key: string]: boolean } = {
    anomaly: true,
    stats: true,
    netflow: true,
  };
  const [filters, setFilters] = createStore({
    query: "",
  });
  const [analyticsLoading, setAnalyticsLoading] = createSignal(false);
  let eventsPerMinuteRef!: HTMLCanvasElement;
  let severityStackRef!: HTMLCanvasElement;
  let topTalkerSrcRef!: HTMLCanvasElement;
  let topTalkerDstRef!: HTMLCanvasElement;
  let topSignaturesRef!: HTMLCanvasElement;
  const chartRegistry: { [key: string]: Chart } = {};
  const signatureSparklines: Record<string, Chart> = {};
  const sparklineRefs: Record<string, HTMLCanvasElement | undefined> = {};
  const [sparklineVersion, setSparklineVersion] = createSignal(0);
  const [topSignaturesRows, setTopSignaturesRows] = createSignal<
    { key: string; count: number }[]
  >([]);
  let rid = 0;
  const [searchParams, setSearchParams] = useSearchParams<{
    sensor?: string;
    q?: string;
  }>();

  createEffect(() => {
    const _ = TIME_RANGE();
    refresh();
    refreshAnalytics();
  });

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
  let protocolsPieChartRef: HTMLCanvasElement | undefined;

  function initChart() {
    if (histogram) {
      histogram.destroy();
    }
    buildChart();
  }

  onCleanup(() => {
    API.cancelAllSse();
    Object.values(chartRegistry).forEach((chart) => chart.destroy());
    Object.values(signatureSparklines).forEach((chart) => chart.destroy());
    if (histogram) histogram.destroy();
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
    API.cancelAllSse?.();
    setVersion((version) => version + 1);
    const q = buildQueryString();

    const aggRequests = [
      { set: setTopAlerts, field: "alert.signature", q: "event_type:alert" },
      { set: setTopDnsRequests, field: "dns.rrname", q: "event_type:dns dns.type:query" },
      { set: setProtocols, field: "proto", q: "event_type:flow", special: "protocols" },
      { set: setTopTlsSni, field: "tls.sni", q: "event_type:tls" },
      { set: setTopQuicSni, field: "quic.sni", q: "event_type:quic" },
      { set: setTopSourceIp, field: "src_ip", q: "event_type:flow" },
      { set: setTopDestIp, field: "dest_ip", q: "event_type:flow" },
      { set: setTopSourcePort, field: "src_port", q: "event_type:flow" },
      { set: setTopDestPort, field: "dest_port", q: "event_type:flow" },
    ];

    for (const req of aggRequests) {
      loadingTracker(setLoading, async () => {
        const request: AggRequest = {
          field: req.field,
          size: 10,
          order: "desc",
          time_range: TIME_RANGE(),
          q: [q, req.q].filter(Boolean).join(" "),
        };
        if (req.set === setProtocols) {
          setProtocols("loading", true);
          setProtocols("data", []);
          await API.getSseAgg(request, version, (data: any) => {
            if (data) {
              if (protocols.data.length === 0) {
                setProtocols("data", data.rows);
              } else {
                const labels = data.rows.map((e: any) => e.key);
                const dataset = data.rows.map((e: any) => e.count);
                const chart = Chart.getChart(protocolsPieChartRef!);
                if (chart) {
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
              }
            }
          }).finally(() => setProtocols("loading", false));
        } else {
          req.set("loading", true);
          await API.getSseAgg(request, version, (data: any) => {
            if (data === null) {
              req.set("loading", false);
            } else if (data) {
              req.set("timestamp", dayjs(data.earliest_ts));
              req.set("rows", data.rows);
            }
          }).finally(() => req.set("loading", false));
        }
      });
    }

    fetchEventsHistogram(q);
  }

  async function fetchEventsHistogram(q: string) {
    initChart();
    const eventTypes = await API.getEventTypes({
      time_range: TIME_RANGE(),
    });
    let labels: number[] = [];
    for (const row of eventTypes) {
      const request = {
        time_range: TIME_RANGE(),
        event_type: row,
        query_string: q,
      };
      loadingTracker(setLoading, async () => {
        setEventsOverTimeLoading((v) => v + 1);
        const response = await API.histogramTime(request);
        if (labels.length === 0) {
          response.data.forEach((e) => {
            labels.push(e.time);
          });
          if (histogram) histogram.data.labels = labels;
        }
        if (response.data.length !== labels.length) {
          console.error("Label and data mismatch");
        } else {
          const values = response.data.map((e) => e.count);
          const hidden = hiddenTypes[row];
          const colorIdx = histogram?.data.datasets.length ?? 0;
          histogram?.data.datasets.push({
            data: values,
            label: row,
            pointRadius: 0,
            hidden,
            backgroundColor: Colors[colorIdx % Colors.length],
            borderColor: Colors[colorIdx % Colors.length],
          });
          histogram?.update();
        }
      }).finally(() => setEventsOverTimeLoading((v) => v - 1));
    }
  }

  function buildChart() {
    const ctx = getChartCanvasElement("histogram");
    const config: ChartConfiguration = {
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
                const label = context.dataset.label;
                const value = context.parsed.y;
                return value === 0 ? null : `${label}: ${value}`;
              },
            },
            itemSort: function (a: any, b: any) {
              return b.raw - a.raw;
            },
            filter: function (item: any) {
              return item.datasetIndex < 6;
            },
          },
          legend: {
            display: true,
            position: "top",
            onClick: (_e, legendItem, legend) => {
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
    histogram = new Chart(ctx, config);
  }

  function upsertChart(
    key: string,
    canvas: HTMLCanvasElement | undefined,
    config: ChartConfiguration,
  ) {
    if (!canvas) return;
    if (chartRegistry[key]) chartRegistry[key].destroy();
    chartRegistry[key] = new Chart(canvas, config);
  }

  function splitQuery(q: string): string[] {
    const out: string[] = [];
    q.replace(/"([^"]*)"|(\S+)/g, (_match, quoted, bare) => {
      out.push(quoted ?? bare);
      return "";
    });
    return out;
  }

  function addFilter(fragment: string) {
    const tokens = splitQuery(searchParams.q || filters.query || "");
    if (!tokens.includes(fragment)) {
      tokens.push(fragment);
    }
    const next = tokens.join(" ");
    setFilters("query", next);
    setSearchParams({ sensor: searchParams.sensor, q: next || undefined });
    refreshAnalytics();
  }

  function removeFilter(fragment: string) {
    const tokens = splitQuery(filters.query);
    const next = tokens.filter((token) => token !== fragment).join(" ");
    setFilters("query", next);
    setSearchParams({ sensor: searchParams.sensor, q: next || undefined });
    refreshAnalytics();
  }

  function handleTableRowClick(field: string | undefined, value: any) {
    if (!field) return;
    const encodedValue = typeof value === "string" && value.includes(" ") ? `"${value}"` : value;
    addFilter(`${field}:${encodedValue}`);
  }

  async function refreshAnalytics() {
    const my = ++rid;
    const queryString = buildQueryString();
    setAnalyticsLoading(true);
    try {
      await Promise.all([
        loadEventsPerMinute(my, queryString),
        loadSeverityStack(my, queryString),
        loadTopTalkers(my, queryString),
        loadTopSignatures(my, queryString),
      ]);
    } finally {
      if (my === rid) setAnalyticsLoading(false);
    }
  }

  async function loadEventsPerMinute(requestId: number, queryString: string) {
    const response = await API.histogramTime({
      time_range: TIME_RANGE(),
      interval: "1m",
      event_type: "alert",
      query_string: queryString || undefined,
    });
    if (requestId !== rid) return;
    const points = response.data.map((d) => ({
      x: new Date(d.time * 1000),
      y: d.count,
    }));
    const avg =
      points.length > 0
        ? points.reduce((acc, item) => acc + item.y, 0) / points.length
        : 0;
    upsertChart("eventsPerMinute", eventsPerMinuteRef, {
      type: "bar",
      data: {
        datasets: [
          {
            label: "Events per minute",
            data: points,
            backgroundColor: "rgba(46, 120, 210, 0.35)",
            borderColor: "rgba(46, 120, 210, 1)",
          },
          {
            type: "line",
            label: "Average",
            data: points.map((p) => ({ x: p.x, y: avg })),
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
        parsing: false,
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
    });
  }

  async function loadSeverityStack(requestId: number, queryString: string) {
    const res = await API.histogramSeverity({
      time_range: TIME_RANGE(),
      interval: "5m",
      query_string: queryString || undefined,
    });
    if (requestId !== rid) return;
    const buckets = res.per_5m.buckets;
    const labels = buckets.map((b) => new Date(b.key));
    const per = (sev: string | number) =>
      buckets.map((b: any) => b.sev.buckets.find((x: any) => x.key == sev)?.doc_count || 0);
    const datasets = [
      { label: "High", color: "#d32f2f", data: per(1) },
      { label: "Medium", color: "#f9a825", data: per(2) },
      { label: "Low", color: "#388e3c", data: per(3) },
    ].map((s) => ({
      ...s,
      fill: true,
      stack: "sev",
      tension: 0.3,
      backgroundColor: s.color + "66",
      borderColor: s.color,
    }));
    upsertChart("severityStack", severityStackRef, {
      type: "line",
      data: { labels, datasets },
      options: {
        parsing: false,
        scales: { x: { type: "time" }, y: { stacked: true } },
        responsive: true,
        maintainAspectRatio: false,
        onClick: (_evt, elements) => {
          const i = elements?.[0]?.datasetIndex;
          if (i == null) return;
          addFilter(`alert.severity:${[1, 2, 3][i]}`);
        },
      },
    });
  }

  async function loadTopTalkers(requestId: number, queryString: string) {
    const baseRequest = {
      size: 10,
      time_range: TIME_RANGE(),
      q: [queryString, "event_type:alert"].filter(Boolean).join(" "),
    } as AggRequest;
    const [src, dst] = await Promise.all([
      fetchAgg({ ...baseRequest, field: "src_ip" }),
      fetchAgg({ ...baseRequest, field: "dest_ip" }),
    ]);
    if (requestId !== rid) return;
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
            const first = elements?.[0];
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

  async function loadTopSignatures(requestId: number, queryString: string) {
    const response = await fetchAgg({
      field: "alert.signature",
      size: 10,
      order: "desc",
      time_range: TIME_RANGE(),
      q: [queryString, "event_type:alert"].filter(Boolean).join(" "),
    });
    if (requestId !== rid) return;
    setTopSignaturesRows(response.rows);
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

  async function loadSignatureTrend(signature: string, queryString: string) {
    const response = await API.histogramTime({
      time_range: TIME_RANGE(),
      interval: "5m",
      event_type: "alert",
      query_string: [queryString, `alert.signature:"${signature}"`]
        .filter(Boolean)
        .join(" "),
    });
    const labels = response.data.map((d) => dayjs.unix(d.time).toDate());
    const counts = response.data.map((d) => d.count);
    const ref = sparklineRefs[signature];
    if (!ref) return;
    if (signatureSparklines[signature]) {
      signatureSparklines[signature].destroy();
    }
    signatureSparklines[signature] = new Chart(ref, {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            data: counts,
            borderColor: "rgba(46, 120, 210, 1)",
            backgroundColor: "rgba(46, 120, 210, 0.1)",
            pointRadius: 0,
            tension: 0.4,
          },
        ],
      },
      options: {
        animation: false,
        parsing: false,
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        scales: { x: { display: false }, y: { display: false } },
      },
    });
  }

  createEffect(() => {
    const rows = topSignaturesRows();
    const queryString = buildQueryString();
    sparklineVersion();
    const keys = new Set(rows.map((row) => row.key));
    Object.keys(signatureSparklines).forEach((key) => {
      if (!keys.has(key)) {
        signatureSparklines[key].destroy();
        delete signatureSparklines[key];
      }
    });
    rows.forEach((row) => loadSignatureTrend(row.key, queryString));
  });

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
                    {splitQuery(filters.query)
                      .filter(Boolean)
                      .map((item) => (
                        <span class="badge bg-secondary filter-tag d-flex align-items-center gap-2">
                          <span>{item}</span>
                          <button
                            type="button"
                            class="btn-close btn-close-white btn-sm"
                            aria-label="Remove"
                            onClick={() => removeFilter(item)}
                          ></button>
                        </span>
                      ))}
                  </div>
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
                            <div class="chart-container" style="position: relative; height: 220px;">
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
                              <span class="badge bg-info text-dark ms-2">click-to-filter</span>
                            </div>
                            <div class="chart-container" style="position: relative; height: 220px;">
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
                            <div class="chart-container" style="position: relative; height: 200px;">
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
                            <div class="chart-container" style="position: relative; height: 200px;">
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
                              <span class="badge bg-warning text-dark ms-2">+ trend sparkline</span>
                            </div>
                            <div class="chart-container" style="position: relative; height: 240px;">
                              <canvas ref={topSignaturesRef}></canvas>
                            </div>
                            <div class="mt-3 list-group list-group-flush">
                              {topSignaturesRows().map((row) => (
                                <div class="list-group-item d-flex align-items-center gap-3">
                                  <div class="flex-grow-1">
                                    <div class="fw-semibold">{row.key}</div>
                                    <div class="text-muted small">{row.count} events</div>
                                  </div>
                                  <div style="width: 120px; height: 40px;">
                                    <canvas
                                      ref={(el) => {
                                        sparklineRefs[row.key] = el;
                                        setSparklineVersion((v) => v + 1);
                                      }}
                                    ></canvas>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </Card.Body>
                </Card>
              </div>
              <div class="col-12">
                <Card class="shadow-sm">
                  <Card.Header class="d-flex align-items-center">
                    <b>Events by Type Over Time</b>
                    <Show when={eventsOverTimeLoading() > 0}>
                      <div class="ms-auto text-muted d-flex align-items-center gap-2">
                        <span class="spinner-border spinner-border-sm" aria-hidden="true"></span>
                        <span>Обновление</span>
                      </div>
                    </Show>
                  </Card.Header>
                  <Card.Body>
                    <div class="chart-container" style="position: relative; height: 400px;">
                      <canvas id="histogram" style="height: 400px; width: 100%;"></canvas>
                    </div>
                  </Card.Body>
                </Card>
              </div>
              <div class="col-lg-3">
                <Card class="shadow-sm h-100">
                  <Card.Header class="d-flex align-items-center">
                    <b>Трафик по протоколам</b>
                    <Show when={protocols.loading}>
                      <div class="ms-auto text-muted d-flex align-items-center gap-2">
                        <span class="spinner-border spinner-border-sm" aria-hidden="true"></span>
                        <span>Обновление</span>
                      </div>
                    </Show>
                  </Card.Header>
                  <Card.Body>
                    <Show
                      when={protocols.data.length > 0}
                      fallback={<div class="text-muted">No data available.</div>}
                    >
                      <PieChart data={protocols.data} ref={protocolsPieChartRef} />
                    </Show>
                  </Card.Body>
                </Card>
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
                      onRowClick={handleTableRowClick}
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
                      onRowClick={handleTableRowClick}
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
                      onRowClick={handleTableRowClick}
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
                      onRowClick={handleTableRowClick}
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
                      onRowClick={handleTableRowClick}
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
                      onRowClick={handleTableRowClick}
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
                      onRowClick={handleTableRowClick}
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
                      onRowClick={handleTableRowClick}
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

function PieChart(props: { data: any[]; ref?: HTMLCanvasElement }) {
  const chartId = createUniqueId();
  let chart: Chart | null = null;

  createEffect(() => {
    const element = getChartCanvasElement(chartId);
    if (chart) {
      chart.destroy();
    }
    chart = new Chart(element, {
      type: "pie",
      data: {
        labels: props.data.map((e) => e.key),
        datasets: [
          {
            data: props.data.map((e) => e.count),
            backgroundColor: props.data.map((_, i) => Colors[i % Colors.length]),
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
              if (chart) {
                chart.tooltip.setActiveElements([activeElement]);
                chart.update();
              }
            },
          },
        },
      },
    });
  });

  onCleanup(() => {
    if (chart) chart.destroy();
  });

  return (
    <div class="chart-container" style="height: 180px; position: relative;">
      <canvas
        id={chartId}
        ref={props.ref}
        style="max-height: 150px; height: 150px;"
      ></canvas>
    </div>
  );
}
