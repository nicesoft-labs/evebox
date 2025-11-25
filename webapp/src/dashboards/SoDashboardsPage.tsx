// SPDX-FileCopyrightText: (C) 2024 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

import { useSearchParams } from "@solidjs/router";
import {
  Button,
  Card,
  Col,
  Form,
  OverlayTrigger,
  Row,
  Tooltip,
} from "solid-bootstrap";
import {
  For,
  Show,
  createEffect,
  createMemo,
  createSignal,
  onCleanup,
} from "solid-js";
import { createStore } from "solid-js/store";
import { Chart, ChartConfiguration } from "chart.js";
import "chartjs-adapter-date-fns";
import { TIME_RANGE, SET_TIME_RANGE } from "../Top";
import { Colors } from "../common/colors";
import { API, AggResponseRow, fetchAgg, get } from "../api";
import { addError } from "../Notifications";

interface FilterState {
  sensor: string;
  severity: string[];
  ip: string;
  signature: string;
  proto: string;
  port: string;
}

interface ChartContextEntry {
  key: string;
  title: string;
  description: string;
}

interface SignatureRow {
  key: string;
  count: number;
}

const chartBaseOptions = {
  animation: { duration: 300 },
  parsing: false,
  maintainAspectRatio: false,
  plugins: {
    legend: { position: "bottom" as const },
    tooltip: { mode: "nearest" as const, intersect: false },
  },
  scales: {
    x: { grid: { color: "#eee" } },
    y: { grid: { color: "#eee" } },
  },
};

function severityPalette() {
  return {
    low: "rgba(0, 176, 80, 0.6)",
    medium: "rgba(255, 193, 7, 0.6)",
    high: "rgba(220, 53, 69, 0.6)",
  };
}

function protocolColor(proto: string) {
  const mapping: Record<string, string> = {
    tcp: "#2e78d2",
    udp: "#4caf50",
    icmp: "#9e9e9e",
    quic: "#ff9800",
  };
  return mapping[proto.toLowerCase()] || "#607d8b";
}

function palette(count: number) {
  return Array.from({ length: count }, (_, idx) => Colors[idx % Colors.length]);
}

function emptyChartConfig(message: string): ChartConfiguration {
  return {
    type: "bar",
    data: { labels: [], datasets: [] },
    options: {
      ...chartBaseOptions,
      plugins: {
        ...chartBaseOptions.plugins,
        legend: { display: false },
        tooltip: { enabled: false },
        annotation: {},
      },
    },
    plugins: [
      {
        id: "no-data",
        afterDraw: (chart) => {
          const { ctx, chartArea } = chart;
          if (!chartArea) return;
          ctx.save();
          ctx.fillStyle = "#999";
          ctx.textAlign = "center";
          ctx.font = "14px sans-serif";
          ctx.fillText(message, (chartArea.left + chartArea.right) / 2, (chartArea.top + chartArea.bottom) / 2);
        },
      },
    ],
  } as ChartConfiguration;
}

export function SoDashboardsPage() {
  const [searchParams, setSearchParams] = useSearchParams<{ q?: string }>();
  const [chartRegistry, setChartRegistry] = createSignal<Record<string, Chart>>({});
  const chartRefs: Record<string, HTMLCanvasElement | undefined> = {};
  const sparklineRefs: Record<string, HTMLCanvasElement | undefined> = {};
  const [sparklineCharts, setSparklineCharts] = createSignal<Record<string, Chart>>({});
  const [signatureRows, setSignatureRows] = createSignal<SignatureRow[]>([]);
  const [loading, setLoading] = createSignal(false);

  const [filters, setFilters] = createStore<FilterState>({
    sensor: "",
    severity: [],
    ip: "",
    signature: "",
    proto: "",
    port: "",
  });

  const chartDefinitions = createMemo<ChartContextEntry[]>(() => [
    { key: "eventsPerMinute", title: "Events per Minute", description: "Оповещения по минутам с усреднением" },
    { key: "severityStack", title: "Severity over Time", description: "Распределение Low/Med/High" },
    { key: "topTalkersSrc", title: "Top Talkers · Src", description: "Источник трафика" },
    { key: "topTalkersDst", title: "Top Talkers · Dst", description: "Получатели трафика" },
    { key: "topSignatures", title: "Top Signatures", description: "Популярные сигнатуры с трендом" },
    { key: "protocolMix", title: "Protocol Mix", description: "Распределение протоколов" },
    { key: "dnsStats", title: "DNS / HTTP / TLS", description: "Частые типы запросов и ответов" },
    { key: "heatmap", title: "Heatmap Час×День", description: "Плотность событий по дням недели" },
    { key: "flowDuration", title: "Flow Duration", description: "Длительность и байты" },
    { key: "sankey", title: "Src → Signature → Dst", description: "Связи источников, сигнатур и получателей" },
  ]);

  createEffect(() => {
    TIME_RANGE();
    searchParams.q;
    JSON.stringify(filters);
    refreshAllCharts();
  });

  onCleanup(() => {
    Object.values(chartRegistry()).forEach((chart) => chart.destroy());
    Object.values(sparklineCharts()).forEach((chart) => chart.destroy());
  });

  function buildQueryString(extra: string[] = [], onlyAlerts = false) {
    const tokens: string[] = [];
    if (filters.sensor) tokens.push(`host:${filters.sensor}`);
    if (filters.severity.length) tokens.push(`alert.severity:(${filters.severity.join(" OR ")})`);
    if (filters.ip) tokens.push(`ip:${filters.ip}`);
    if (filters.signature) tokens.push(`alert.signature:"${filters.signature}"`);
    if (filters.proto) tokens.push(`proto:${filters.proto}`);
    if (filters.port) tokens.push(`port:${filters.port}`);
    if (searchParams.q) tokens.push(searchParams.q);
    tokens.push(...extra);
    if (onlyAlerts) tokens.push("event_type:alert");
    return tokens.join(" ").trim();
  }

  function addFilter(fragment: string) {
    const tokens = (searchParams.q || "").split(" ").filter((t) => t.trim().length > 0);
    if (!tokens.includes(fragment)) {
      tokens.push(fragment);
    }
    setSearchParams({ ...searchParams, q: tokens.join(" ") });
  }

  function setChart(key: string, config: ChartConfiguration) {
    const canvas = chartRefs[key];
    if (!canvas) return;
    const existing = chartRegistry()[key];
    if (existing) existing.destroy();
    const chart = new Chart(canvas, config);
    setChartRegistry((prev) => ({ ...prev, [key]: chart }));
  }

  function setSparkline(key: string, config: ChartConfiguration) {
    const canvas = sparklineRefs[key];
    if (!canvas) return;
    const existing = sparklineCharts()[key];
    if (existing) existing.destroy();
    const chart = new Chart(canvas, config);
    setSparklineCharts((prev) => ({ ...prev, [key]: chart }));
  }

  async function loadEventsPerMinute() {
    try {
      const query_string = buildQueryString([], true);
      const response = await API.histogramTime({
        time_range: TIME_RANGE(),
        interval: "1m",
        event_type: "alert",
        query_string,
      });
      const points = response.data || [];
      if (!points.length) {
        setChart("eventsPerMinute", emptyChartConfig("Нет данных за выбранный период"));
        return;
      }
      const labels = points.map((p) => new Date(p.time));
      const values = points.map((p) => p.count);
      const avg = values.reduce((a, b) => a + b, 0) / values.length;
      setChart("eventsPerMinute", {
        type: "bar",
        data: {
          labels,
          datasets: [
            {
              label: "События",
              data: values,
              backgroundColor: "rgba(46, 120, 210, 0.4)",
              borderColor: "rgba(46, 120, 210, 1)",
            },
            {
              type: "line",
              label: "Среднее",
              data: values.map(() => avg),
              borderColor: "rgba(46, 120, 210, 1)",
              borderWidth: 2,
              pointRadius: 0,
              fill: false,
            },
          ],
        },
        options: {
          ...chartBaseOptions,
          scales: { ...chartBaseOptions.scales, x: { type: "time", grid: { color: "#eee" } }, y: { beginAtZero: true, grid: { color: "#eee" } } },
          onClick: () => addFilter("event_type:alert"),
        },
      });
    } catch (err) {
      console.error(err);
      addError("Ошибка загрузки данных Events per Minute");
      setChart("eventsPerMinute", emptyChartConfig("Ошибка загрузки данных"));
    }
  }

  async function loadSeverityStack() {
    const sevColors = severityPalette();
    const severities: Array<[string, string]> = [
      ["low", sevColors.low],
      ["medium", sevColors.medium],
      ["high", sevColors.high],
    ];
    try {
      const datasets: any[] = [];
      let labels: Date[] = [];
      for (const [level, color] of severities) {
        const response = await API.histogramTime({
          time_range: TIME_RANGE(),
          interval: "5m",
          event_type: "alert",
          query_string: buildQueryString([`alert.severity:${level}`], true),
        });
        const points = response.data || [];
        if (!labels.length) labels = points.map((p) => new Date(p.time));
        datasets.push({
          label: level,
          data: points.map((p) => p.count),
          fill: true,
          tension: 0.3,
          backgroundColor: color,
          borderColor: color.replace("0.6", "1"),
          stack: "sev",
        });
      }
      if (!labels.length) {
        setChart("severityStack", emptyChartConfig("Нет данных за выбранный период"));
        return;
      }
      setChart("severityStack", {
        type: "line",
        data: { labels, datasets },
        options: {
          ...chartBaseOptions,
          scales: { x: { type: "time", stacked: true, grid: { color: "#eee" } }, y: { stacked: true, grid: { color: "#eee" } } },
          onClick: (evt, elements) => {
            if (!elements.length) return;
            const datasetIndex = elements[0].datasetIndex;
            const level = severities[datasetIndex]?.[0];
            if (level) {
              addFilter(`alert.severity:${level}`);
              refreshAllCharts();
            }
          },
        },
      });
    } catch (err) {
      console.error(err);
      addError("Ошибка загрузки Severity over Time");
      setChart("severityStack", emptyChartConfig("Ошибка загрузки данных"));
    }
  }

  async function loadTopTalkers(field: string, key: string) {
    try {
      const response = await fetchAgg({
        field,
        size: 10,
        time_range: TIME_RANGE(),
        q: buildQueryString([], true),
      });
      const rows = (response.rows || []) as AggResponseRow[];
      if (!rows.length) {
        setChart(key, emptyChartConfig("Нет данных за выбранный период"));
        return;
      }
      setChart(key, {
        type: "bar",
        data: {
          labels: rows.map((r) => r.key),
          datasets: [
            {
              label: field,
              data: rows.map((r) => r.count),
              backgroundColor: palette(rows.length),
            },
          ],
        },
        options: {
          ...chartBaseOptions,
          indexAxis: "y",
          onClick: (_evt, elements) => {
            if (!elements.length) return;
            const label = (elements[0].element as any).$context.raw || (elements[0].element as any).$context.label;
            addFilter(`${field}:${label}`);
            refreshAllCharts();
          },
        },
      });
    } catch (err) {
      console.error(err);
      addError("Ошибка загрузки Top Talkers");
      setChart(key, emptyChartConfig("Ошибка загрузки данных"));
    }
  }

  async function loadTopSignatures() {
    try {
      const response = await fetchAgg({
        field: "alert.signature",
        size: 10,
        time_range: TIME_RANGE(),
        q: buildQueryString([], true),
      });
      const rows = (response.rows || []) as AggResponseRow[];
      setSignatureRows(rows.map((r) => ({ key: r.key, count: r.count })));
      setChart("topSignatures", {
        type: "bar",
        data: {
          labels: rows.map((r) => r.key),
          datasets: [
            { label: "Сигнатуры", data: rows.map((r) => r.count), backgroundColor: palette(rows.length) },
          ],
        },
        options: {
          ...chartBaseOptions,
          indexAxis: "y",
          onClick: (_evt, elements) => {
            if (!elements.length) return;
            const label = (elements[0].element as any).$context.label;
            addFilter(`alert.signature:"${label}"`);
            refreshAllCharts();
          },
        },
      });
      await Promise.all(
        rows.map(async (row) => {
          try {
            const histogram = await API.histogramTime({
              time_range: TIME_RANGE(),
              interval: "10m",
              event_type: "alert",
              query_string: buildQueryString([`alert.signature:"${row.key}"`], true),
            });
            const labels = (histogram.data || []).map((p) => new Date(p.time));
            const values = (histogram.data || []).map((p) => p.count);
            setSparkline(row.key, {
              type: "line",
              data: { labels, datasets: [{ data: values, borderColor: "#2e78d2", backgroundColor: "rgba(46,120,210,0.2)", fill: true, tension: 0.3, pointRadius: 0 }] },
              options: {
                ...chartBaseOptions,
                plugins: { legend: { display: false }, tooltip: { enabled: false } },
                scales: { x: { display: false }, y: { display: false } },
              },
            });
          } catch (err) {
            console.error(err);
          }
        }),
      );
    } catch (err) {
      console.error(err);
      addError("Ошибка загрузки Top Signatures");
      setSignatureRows([]);
    }
  }

  async function loadProtocolMix() {
    try {
      const response = await fetchAgg({
        field: "proto",
        size: 10,
        time_range: TIME_RANGE(),
        q: buildQueryString([], false),
      });
      const rows = (response.rows || []) as AggResponseRow[];
      if (!rows.length) {
        setChart("protocolMix", emptyChartConfig("Нет данных"));
        return;
      }
      setChart("protocolMix", {
        type: "doughnut",
        data: {
          labels: rows.map((r) => r.key),
          datasets: [
            {
              label: "Протокол",
              data: rows.map((r) => r.count),
              backgroundColor: rows.map((r) => protocolColor(`${r.key}`)),
            },
          ],
        },
        options: {
          ...chartBaseOptions,
          onClick: (_evt, elements) => {
            if (!elements.length) return;
            const idx = elements[0].index;
            const value = rows[idx]?.key;
            if (value) {
              addFilter(`proto:${value}`);
              refreshAllCharts();
            }
          },
          plugins: {
            ...chartBaseOptions.plugins,
            tooltip: {
              callbacks: {
                label: (ctx) => `${ctx.label} — ${ctx.raw} событий`,
              },
            },
          },
        },
      });
    } catch (err) {
      console.error(err);
      addError("Ошибка загрузки Protocol Mix");
      setChart("protocolMix", emptyChartConfig("Ошибка загрузки"));
    }
  }

  async function loadDnsHttpTls() {
    try {
      const queries: Array<[string, string]> = [
        ["dns.rrtype", "dns"],
        ["dns.rrname", "dns"],
        ["http.method", "http"],
        ["http.status", "http"],
        ["tls.version", "tls"],
        ["tls.cipher", "tls"],
      ];
      const datasets: any[] = [];
      for (const [field, prefix] of queries) {
        const response = await fetchAgg({
          field,
          size: 6,
          time_range: TIME_RANGE(),
          q: buildQueryString([], prefix === "dns" ? false : true),
        });
        const rows = (response.rows || []) as AggResponseRow[];
        rows.slice(0, 5).forEach((row) => {
          datasets.push({
            label: `${field}: ${row.key}`,
            data: [{ x: `${field}`, y: row.count }],
            backgroundColor: palette(1)[0],
            _field: field,
            _value: row.key,
          });
        });
      }
      if (!datasets.length) {
        setChart("dnsStats", emptyChartConfig("Нет данных"));
        return;
      }
      setChart("dnsStats", {
        type: "bar",
        data: { labels: queries.map((q) => q[0]), datasets },
        options: {
          ...chartBaseOptions,
          indexAxis: "y",
          onClick: (_evt, elements) => {
            if (!elements.length) return;
            const dataset = datasets[elements[0].datasetIndex];
            if (dataset?._field && dataset?._value) {
              addFilter(`${dataset._field}:${dataset._value}`);
              refreshAllCharts();
            }
          },
        },
      });
    } catch (err) {
      console.error(err);
      addError("Ошибка загрузки DNS/HTTP/TLS");
      setChart("dnsStats", emptyChartConfig("Ошибка загрузки"));
    }
  }

  async function loadHeatmap() {
    try {
      const response = await get("api/analytics", {
        time_range: TIME_RANGE(),
        q: buildQueryString(),
        agg: "heatmap",
      });
      const buckets = response.data?.buckets || [];
      if (!buckets.length) {
        setChart("heatmap", emptyChartConfig("Нет данных"));
        return;
      }
      const data = buckets.map((b: any) => ({ x: b.hour, y: b.day, v: b.count }));
      setChart("heatmap", {
        type: "bubble",
        data: {
          datasets: [
            {
              label: "Часы/Дни",
              data: data.map((d: any) => ({ x: d.x, y: d.y, r: Math.max(3, d.v / 5) })),
              backgroundColor: data.map((d: any) => `rgba(${Math.min(255, d.v * 5)}, ${Math.max(50, 200 - d.v * 2)}, 70, 0.7)`),
            },
          ],
        },
        options: {
          ...chartBaseOptions,
          scales: {
            x: { type: "linear", min: 0, max: 23, ticks: { stepSize: 1 } },
            y: { type: "linear", min: 1, max: 7, ticks: { stepSize: 1 } },
          },
          plugins: {
            ...chartBaseOptions.plugins,
            tooltip: {
              callbacks: {
                label: (ctx) => {
                  const dayNames = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"];
                  return `${dayNames[(ctx.raw as any).y - 1]}, ${(ctx.raw as any).x}:00 — ${(ctx.raw as any).v || (ctx.raw as any).r * 5} событий`;
                },
              },
            },
          },
          onClick: (_evt, elements) => {
            if (!elements.length) return;
            const raw = (elements[0].element as any).$context.raw as any;
            addFilter(`@timestamp.hour:${raw.x}`);
            refreshAllCharts();
          },
        },
      });
    } catch (err) {
      console.error(err);
      addError("Ошибка загрузки тепловой карты");
      setChart("heatmap", emptyChartConfig("Ошибка загрузки"));
    }
  }

  async function loadFlows() {
    try {
      const durationAgg = await fetchAgg({
        field: "flow.duration",
        size: 20,
        time_range: TIME_RANGE(),
        q: buildQueryString([], false),
      });
      const durations = (durationAgg.rows || []) as AggResponseRow[];
      setChart("flowDuration", {
        type: "bar",
        data: {
          labels: durations.map((r) => r.key),
          datasets: [
            {
              label: "Длительность",
              data: durations.map((r) => r.count),
              backgroundColor: "rgba(46,120,210,0.4)",
            },
          ],
        },
        options: {
          ...chartBaseOptions,
          onClick: (_evt, elements) => {
            if (!elements.length) return;
            const label = (elements[0].element as any).$context.label;
            addFilter(`flow.duration:${label}`);
            refreshAllCharts();
          },
        },
      });

      const scatterResponse = await get("api/analytics", {
        time_range: TIME_RANGE(),
        q: buildQueryString([], false),
        agg: "flow-bytes",
      });
      const points = scatterResponse.data?.points || [];
      setChart("bytesScatter", {
        type: "scatter",
        data: {
          datasets: [
            {
              label: "Флоу",
              data: points.map((p: any) => ({ x: p.bytes_toserver, y: p.bytes_toclient, src: p.src_ip, dst: p.dest_ip })),
              backgroundColor: "rgba(46,120,210,0.5)",
            },
          ],
        },
        options: {
          ...chartBaseOptions,
          scales: {
            x: { title: { text: "to server", display: true }, grid: { color: "#eee" } },
            y: { title: { text: "to client", display: true }, grid: { color: "#eee" } },
          },
          plugins: {
            ...chartBaseOptions.plugins,
            tooltip: {
              callbacks: {
                label: (ctx) => {
                  const raw = ctx.raw as any;
                  return `${raw.src} → ${raw.dst} (${raw.x}/${raw.y})`;
                },
              },
            },
          },
        },
      });
    } catch (err) {
      console.error(err);
      addError("Ошибка загрузки Flow статистики");
      setChart("flowDuration", emptyChartConfig("Ошибка загрузки"));
      setChart("bytesScatter", emptyChartConfig("Ошибка загрузки"));
    }
  }

  async function loadSankey() {
    try {
      const response = await get("api/aggregations", {
        time_range: TIME_RANGE(),
        q: buildQueryString([], true),
        field: "src_ip,alert.signature,dest_ip",
        size: 8,
      });
      const rows = response.data?.rows || [];
      if (!rows.length) {
        setChart("sankey", emptyChartConfig("Нет данных"));
        return;
      }
      const labels = rows.map((r: any) => `${r.key[0]} → ${r.key[1]} → ${r.key[2]}`);
      setChart("sankey", {
        type: "bar",
        data: {
          labels,
          datasets: [
            { label: "Связи", data: rows.map((r: any) => r.count), backgroundColor: "rgba(46,120,210,0.6)" },
          ],
        },
        options: {
          ...chartBaseOptions,
          onClick: (_evt, elements) => {
            if (!elements.length) return;
            const raw = rows[elements[0].index];
            if (!raw) return;
            addFilter(`src_ip:${raw.key[0]}`);
            refreshAllCharts();
          },
        },
      });
    } catch (err) {
      console.error(err);
      addError("Ошибка загрузки Sankey");
      setChart("sankey", emptyChartConfig("Ошибка загрузки"));
    }
  }

  async function refreshAllCharts() {
    if (loading()) return;
    setLoading(true);
    await Promise.all([
      loadEventsPerMinute(),
      loadSeverityStack(),
      loadTopTalkers("src_ip", "topTalkersSrc"),
      loadTopTalkers("dest_ip", "topTalkersDst"),
      loadTopSignatures(),
      loadProtocolMix(),
      loadDnsHttpTls(),
      loadHeatmap(),
      loadFlows(),
      loadSankey(),
    ]);
    setLoading(false);
  }

  function applyFilters() {
    const tokens: string[] = [];
    if (filters.sensor) tokens.push(`host:${filters.sensor}`);
    if (filters.severity.length) tokens.push(`alert.severity:(${filters.severity.join(" OR ")})`);
    if (filters.ip) tokens.push(`ip:${filters.ip}`);
    if (filters.signature) tokens.push(`alert.signature:"${filters.signature}"`);
    if (filters.proto) tokens.push(`proto:${filters.proto}`);
    if (filters.port) tokens.push(`port:${filters.port}`);
    setSearchParams({ ...searchParams, q: tokens.join(" ") || undefined });
  }

  function resetFilters() {
    setFilters({ sensor: "", severity: [], ip: "", signature: "", proto: "", port: "" });
    setSearchParams({ q: undefined });
    SET_TIME_RANGE("24h");
  }

  const activeTokens = createMemo(() => (searchParams.q ? searchParams.q.split(" ").filter(Boolean) : []));

  return (
    <div class="p-3">
      <div class="d-flex align-items-center justify-content-between mb-3">
        <div>
          <h3 class="mb-0">Графики</h3>
          <div class="text-muted">Security Onion style dashboards</div>
        </div>
        <div class="d-flex align-items-center gap-2">
          <Button variant="outline-secondary" onClick={() => addFilter("pcap:open")}>Настройки PCAP</Button>
          <Button size="sm" variant="outline-primary" onClick={() => SET_TIME_RANGE("15m")}>15m</Button>
          <Button size="sm" variant="outline-primary" onClick={() => SET_TIME_RANGE("1h")}>1h</Button>
          <Button size="sm" variant="outline-primary" onClick={() => SET_TIME_RANGE("24h")}>24h</Button>
          <Button size="sm" variant="outline-primary" onClick={() => SET_TIME_RANGE("7d")}>7d</Button>
          <Button size="sm" variant="primary" onClick={() => refreshAllCharts()}>↻ Обновить все</Button>
        </div>
      </div>

      <Row>
        <Col md={4} lg={3} class="position-sticky" style="top: 10px; max-width: 320px; height: fit-content;">
          <Card class="mb-3">
            <Card.Header>Фильтр</Card.Header>
            <Card.Body class="d-grid gap-3">
              <Form.Group>
                <Form.Label>Sensor</Form.Label>
                <Form.Control
                  value={filters.sensor}
                  onInput={(e) => setFilters("sensor", e.currentTarget.value)}
                  placeholder="sensor-01"
                />
              </Form.Group>
              <Form.Group>
                <Form.Label>Severity</Form.Label>
                <div class="d-flex flex-wrap gap-2">
                  {(["low", "medium", "high"] as const).map((sev) => (
                    <Form.Check
                      inline
                      type="checkbox"
                      label={sev}
                      checked={filters.severity.includes(sev)}
                      onChange={(e) => {
                        const checked = e.currentTarget.checked;
                        setFilters("severity", (current) => {
                          if (checked) return [...current, sev];
                          return current.filter((s) => s !== sev);
                        });
                      }}
                    />
                  ))}
                </div>
              </Form.Group>
              <Form.Group>
                <Form.Label>IP / подсеть</Form.Label>
                <Form.Control
                  value={filters.ip}
                  onInput={(e) => setFilters("ip", e.currentTarget.value)}
                  placeholder="1.2.3.0/24"
                />
              </Form.Group>
              <Form.Group>
                <Form.Label>Подпись</Form.Label>
                <Form.Control
                  value={filters.signature}
                  onInput={(e) => setFilters("signature", e.currentTarget.value)}
                  placeholder="ET DROP"
                />
              </Form.Group>
              <Form.Group>
                <Form.Label>Протокол</Form.Label>
                <Form.Control
                  value={filters.proto}
                  onInput={(e) => setFilters("proto", e.currentTarget.value)}
                  placeholder="tcp"
                />
              </Form.Group>
              <Form.Group>
                <Form.Label>Порт</Form.Label>
                <Form.Control
                  value={filters.port}
                  onInput={(e) => setFilters("port", e.currentTarget.value)}
                  placeholder="443"
                />
              </Form.Group>
              <div class="d-flex gap-2">
                <Button onClick={applyFilters}>Применить</Button>
                <Button variant="secondary" onClick={resetFilters}>
                  Сбросить
                </Button>
              </div>
            </Card.Body>
          </Card>

          <Card>
            <Card.Header>Операционные метрики</Card.Header>
            <Card.Body>
              <div class="d-flex justify-content-between mb-2"><span>Indexing Lag</span><span class="text-success">OK</span></div>
              <div class="d-flex justify-content-between mb-2"><span>QPS</span><span>~1.2k</span></div>
              <div class="d-flex justify-content-between"><span>Sensor Health</span><span class="text-success">GREEN</span></div>
            </Card.Body>
          </Card>
        </Col>

        <Col md={8} lg={9}>
          <div class="mb-3 d-flex flex-wrap gap-2">
            <Show when={activeTokens().length === 0}>
              <span class="text-muted">Активные фильтры отсутствуют</span>
            </Show>
            <For each={activeTokens()}>{(token) => <Button size="sm" variant="outline-secondary">{token}</Button>}</For>
          </div>

          <Row class="g-3">
            <For each={chartDefinitions()}>
              {(definition) => (
                <Col md={definition.key === "sankey" ? 12 : 6}>
                  <Card class="h-100">
                    <Card.Header class="d-flex justify-content-between align-items-center">
                      <div>ℹ️ {definition.title}</div>
                      <div class="d-flex align-items-center gap-2">
                        <OverlayTrigger
                          placement="left"
                          overlay={<Tooltip>{definition.description}</Tooltip>}
                        >
                          <Button size="sm" variant="outline-secondary">
                            ℹ️
                          </Button>
                        </OverlayTrigger>
                        <Button size="sm" variant="outline-primary" onClick={() => refreshAllCharts()}>
                          ↻
                        </Button>
                      </div>
                    </Card.Header>
                    <Card.Body>
                      {(() => {
                        if (definition.key === "flowDuration") {
                          return (
                            <>
                              <div class="chart-container" style="height: 240px;">
                                <canvas ref={(el) => (chartRefs["flowDuration"] = el || undefined)} />
                              </div>
                              <div class="chart-container mt-3" style="height: 240px;">
                                <canvas ref={(el) => (chartRefs["bytesScatter"] = el || undefined)} />
                              </div>
                            </>
                          );
                        }
                        if (definition.key === "dnsStats") {
                          return (
                            <div class="chart-container" style="height: 260px;">
                              <canvas ref={(el) => (chartRefs["dnsStats"] = el || undefined)} />
                            </div>
                          );
                        }
                        if (definition.key === "sankey") {
                          return (
                            <div class="chart-container" style="height: 260px;">
                              <canvas ref={(el) => (chartRefs["sankey"] = el || undefined)} />
                            </div>
                          );
                        }
                        if (definition.key === "topSignatures") {
                          return (
                            <>
                              <div class="chart-container" style="height: 240px;">
                                <canvas ref={(el) => (chartRefs["topSignatures"] = el || undefined)} />
                              </div>
                              <div class="mt-3">
                                <Card>
                                  <Card.Header>Top Signatures</Card.Header>
                                  <Card.Body class="p-0">
                                    <div class="table-responsive">
                                      <table class="table mb-0 align-middle">
                                        <thead>
                                          <tr>
                                            <th>Signature</th>
                                            <th>Count</th>
                                            <th>Trend</th>
                                          </tr>
                                        </thead>
                                        <tbody>
                                          <For each={signatureRows()}>
                                            {(row) => (
                                              <tr>
                                                <td>
                                                  <Button variant="link" class="p-0" onClick={() => { addFilter(`alert.signature:\"${row.key}\"`); refreshAllCharts(); }}>
                                                    {row.key}
                                                  </Button>
                                                </td>
                                                <td>{row.count}</td>
                                                <td style="width: 120px;">
                                                  <canvas ref={(el) => (sparklineRefs[row.key] = el || undefined)} height={40} />
                                                </td>
                                              </tr>
                                            )}
                                          </For>
                                          <Show when={signatureRows().length === 0}>
                                            <tr>
                                              <td colspan={3} class="text-center text-muted py-3">Нет данных за выбранный период</td>
                                            </tr>
                                          </Show>
                                        </tbody>
                                      </table>
                                    </div>
                                  </Card.Body>
                                </Card>
                              </div>
                            </>
                          );
                        }
                        return (
                          <div class="chart-container" style="height: 240px;">
                            <canvas ref={(el) => (chartRefs[definition.key] = el || undefined)} />
                          </div>
                        );
                      })()}
                    </Card.Body>
                  </Card>
                </Col>
              )}
            </For>
          </Row>
        </Col>
      </Row>
    </div>
  );
}
