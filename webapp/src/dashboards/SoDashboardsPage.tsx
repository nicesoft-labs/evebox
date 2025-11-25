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

interface FilterState {
  sensor: string;
  severity: string[];
  ip: string;
  signature: string;
  proto: string;
  port: string;
}

interface ChartDefinition {
  key: string;
  title: string;
  description: string;
  buildConfig: (seed: number) => ChartConfiguration;
  onClickFilter?: (elements: any) => string | undefined;
}

const baseOptions = {
  animation: false,
  parsing: false,
  maintainAspectRatio: false,
};

function palette(count: number) {
  return Array.from({ length: count }, (_, idx) => Colors[idx % Colors.length]);
}

function primaryColor() {
  return Colors[0] || "#2962FF";
}

function severityPalette() {
  return {
    low: Colors[2] || "#00C853",
    medium: Colors[3] || "#FFAB00",
    high: Colors[1] || "#D50000",
  };
}

function heatColor(value: number) {
  const intensity = Math.min(1, value / 25);
  const red = Math.floor(255 * intensity);
  const green = Math.floor(200 * (1 - intensity));
  return `rgba(${red}, ${green}, 70, 0.7)`;
}

export function SoDashboardsPage() {
  const [searchParams, setSearchParams] = useSearchParams<{ q?: string }>();
  const [chartRegistry, setChartRegistry] = createSignal<Record<string, Chart>>({});
  const [renderSeed, setRenderSeed] = createSignal(0);
  const chartRefs: Record<string, HTMLCanvasElement | undefined> = {};
  const [filters, setFilters] = createStore<FilterState>({
    sensor: "",
    severity: [],
    ip: "",
    signature: "",
    proto: "",
    port: "",
  });

  const chartDefinitions = createMemo<ChartDefinition[]>(() => [
    {
      key: "eventsPerMinute",
      title: "Events per Minute",
      description: "Оповещения по минутам с усреднением",
      buildConfig: (seed) => {
        const labels = buildIntervalLabels(30, "minute");
        const values = labels.map((_, idx) => 30 + ((idx + seed) % 12));
        const avg = values.reduce((a, b) => a + b, 0) / values.length;
        return {
          type: "bar",
          data: {
            labels,
            datasets: [
              {
                label: "Alerts",
                data: values,
                backgroundColor: palette(values.length),
              },
              {
                type: "line",
                label: "Среднее",
                data: values.map(() => avg),
                borderColor: primaryColor(),
                borderWidth: 2,
                fill: false,
              },
            ],
          },
          options: {
            ...baseOptions,
            scales: {
              x: { type: "time" },
              y: { beginAtZero: true },
            },
            onClick: () => addFilter("event_type:alert"),
          },
        } as ChartConfiguration;
      },
    },
    {
      key: "severityStack",
      title: "Severity over Time",
      description: "Распределение Low/Med/High",
      buildConfig: (seed) => {
        const labels = buildIntervalLabels(24, "minute", 5);
        const sevColors = severityPalette();
        const datasets = [
          { label: "Low", color: sevColors.low },
          { label: "Med", color: sevColors.medium },
          { label: "High", color: sevColors.high },
        ].map((entry, idx) => ({
          label: entry.label,
          data: labels.map((_, i) => 5 + ((i + seed + idx * 2) % 10)),
          fill: true,
          tension: 0.3,
          backgroundColor: `${entry.color}66`,
          borderColor: entry.color,
          stack: "sev",
        }));
        return {
          type: "line",
          data: { labels, datasets },
          options: {
            ...baseOptions,
            scales: { x: { type: "time" }, y: { stacked: true } },
            plugins: { legend: { position: "bottom" } },
            onClick: (evt, elements) => {
              if (!elements.length) return;
              const datasetIndex = elements[0].datasetIndex;
              const sev = datasetIndex === 0 ? "low" : datasetIndex === 1 ? "medium" : "high";
              addFilter(`alert.severity:${sev}`);
            },
          },
        } as ChartConfiguration;
      },
    },
    {
      key: "heatmap",
      title: "Heatmap Час×День",
      description: "Плотность событий по дням недели",
      buildConfig: (seed) => {
        const data = buildHeatmap(seed);
        return {
          type: "bubble",
          data: {
            datasets: [
              {
                label: "Часы/Дни",
                data: data.map((item) => ({ x: item.hour, y: item.day, r: item.value / 3 })),
                backgroundColor: data.map((item) => heatColor(item.value)),
              },
            ],
          },
          options: {
            ...baseOptions,
            scales: {
              x: { type: "linear", min: 0, max: 23, ticks: { stepSize: 1 } },
              y: { type: "linear", min: 1, max: 7, ticks: { stepSize: 1 } },
            },
            onClick: (evt, elements) => {
              if (!elements.length) return;
              const raw = (elements[0].element as any).$context.raw as any;
              addFilter(`@timestamp.hour:${raw.x} AND @timestamp.day:${raw.y}`);
            },
          },
        } as ChartConfiguration;
      },
    },
    {
      key: "topTalkersSrc",
      title: "Top Talkers · Src",
      description: "Источник трафика",
      buildConfig: (seed) => buildBarConfig("src_ip", seed, true),
      onClickFilter: (elements) => termFromBar(elements, "src_ip"),
    },
    {
      key: "topTalkersDst",
      title: "Top Talkers · Dst",
      description: "Получатели трафика",
      buildConfig: (seed) => buildBarConfig("dest_ip", seed, true),
      onClickFilter: (elements) => termFromBar(elements, "dest_ip"),
    },
    {
      key: "topSignatures",
      title: "Top Signatures",
      description: "Популярные сигнатуры Suricata",
      buildConfig: (seed) => buildBarConfig("alert.signature", seed, false),
      onClickFilter: (elements) => termFromBar(elements, "alert.signature"),
    },
    {
      key: "protocolMix",
      title: "Protocol Mix",
      description: "Распределение протоколов",
      buildConfig: () => buildDonutConfig(["tcp", "udp", "icmp", "quic"], "proto"),
      onClickFilter: (elements) => pieTerm(elements, ["tcp", "udp", "icmp", "quic"], "proto"),
    },
    {
      key: "dnsQtypes",
      title: "DNS QTypes",
      description: "Частые типы запросов",
      buildConfig: (seed) => buildBarConfig("dns.rrtype", seed, false),
      onClickFilter: (elements) => termFromBar(elements, "dns.rrtype"),
    },
    {
      key: "dnsDomains",
      title: "Top DNS Domains",
      description: "Частые RRname",
      buildConfig: (seed) => buildBarConfig("dns.rrname", seed, true),
      onClickFilter: (elements) => termFromBar(elements, "dns.rrname"),
    },
    {
      key: "httpMethods",
      title: "HTTP Methods",
      description: "Статистика методов",
      buildConfig: () => buildBarConfigFromValues(["GET", "POST", "PUT", "DELETE", "HEAD"], "http.method"),
      onClickFilter: (elements) => termFromBar(elements, "http.method"),
    },
    {
      key: "httpStatus",
      title: "HTTP Status",
      description: "Группы 2xx/3xx/4xx/5xx",
      buildConfig: () => buildBarConfigFromValues(["2xx", "3xx", "4xx", "5xx"], "http.status"),
      onClickFilter: (elements) => termFromBar(elements, "http.status"),
    },
    {
      key: "tlsVersions",
      title: "TLS Versions",
      description: "Версии TLS",
      buildConfig: () => buildDonutConfig(["1.0", "1.1", "1.2", "1.3"], "tls.version"),
      onClickFilter: (elements) => pieTerm(elements, ["1.0", "1.1", "1.2", "1.3"], "tls.version"),
    },
    {
      key: "tlsCiphers",
      title: "TLS Cipher Suites",
      description: "Популярные шифры",
      buildConfig: (seed) => buildBarConfig("tls.cipher", seed, false),
      onClickFilter: (elements) => termFromBar(elements, "tls.cipher"),
    },
    {
      key: "flowDuration",
      title: "Flow Duration Histogram",
      description: "Длительность потоков",
      buildConfig: (seed) => {
        const labels = Array.from({ length: 12 }, (_, i) => `${i * 5}-${(i + 1) * 5}s`);
        const values = labels.map((_, idx) => 3 + ((idx + seed) % 9));
        return buildBar(labels, values, "flow.duration");
      },
      onClickFilter: (elements) => termFromBar(elements, "flow.duration"),
    },
    {
      key: "bytesScatter",
      title: "Bytes In/Out Scatter",
      description: "bytes_toserver vs bytes_toclient",
      buildConfig: (seed) => {
        const points = Array.from({ length: 40 }, (_, i) => ({
          x: (i + 1) * 1000 + seed * 5,
          y: (i % 10) * 1200 + seed * 3,
        }));
        return {
          type: "scatter",
          data: { datasets: [{ label: "Флоу", data: points, backgroundColor: primaryColor() }] },
          options: {
            ...baseOptions,
            scales: { x: { title: { text: "to server", display: true } }, y: { title: { text: "to client", display: true } } },
            onClick: (evt, elements) => {
              if (!elements.length) return;
              const raw = (elements[0].element as any).$context.raw as any;
              addFilter(`bytes_toserver:${Math.round(raw.x)}`);
            },
          },
        } as ChartConfiguration;
      },
    },
    {
      key: "sankey",
      title: "Src → Signature → Dst",
      description: "Псевдо-Sankey по top-N",
      buildConfig: (seed) => {
        const labels = ["Src", "Signature", "Dst"];
        const values = labels.map((_, idx) => 10 + ((idx + seed) % 5));
        return buildBar(labels, values, "pivot");
      },
      onClickFilter: (elements) => termFromBar(elements, "src_ip"),
    },
  ]);

  createEffect(() => {
    // rerender when time range or query changes
    TIME_RANGE();
    searchParams.q;
    setRenderSeed((v) => v + 1);
  });

  createEffect(() => {
    renderCharts();
  });

  onCleanup(() => {
    Object.values(chartRegistry()).forEach((chart) => chart.destroy());
  });

  function buildIntervalLabels(count: number, unit: "minute", step = 1) {
    const now = Date.now();
    return Array.from({ length: count }, (_, idx) => new Date(now - (count - idx) * step * 60 * 1000));
  }

  function buildHeatmap(seed: number) {
    const result: { day: number; hour: number; value: number }[] = [];
    for (let d = 1; d <= 7; d++) {
      for (let h = 0; h < 24; h += 3) {
        result.push({ day: d, hour: h, value: ((h + d + seed) % 20) + 5 });
      }
    }
    return result;
  }

  function buildBarConfig(field: string, seed: number, horizontal: boolean) {
    const labels = Array.from({ length: 10 }, (_, i) => `${field}-${i + 1}`);
    const values = labels.map((_, idx) => 5 + ((idx + seed) % 15));
    return buildBar(labels, values, field, horizontal);
  }

  function buildBarConfigFromValues(values: string[], field: string) {
    const metrics = values.map((v, idx) => ({ v, count: 8 + idx * 2 }));
    return buildBar(
      metrics.map((m) => m.v),
      metrics.map((m) => m.count),
      field,
    );
  }

  function buildDonutConfig(values: string[], field: string) {
    return {
      type: "doughnut",
      data: {
        labels: values,
        datasets: [
          {
            label: field,
            data: values.map((_, idx) => 10 + idx * 5),
            backgroundColor: palette(values.length),
          },
        ],
      },
      options: {
        ...baseOptions,
        onClick: (evt, elements) => {
          const token = pieTerm(elements, values, field);
          if (token) addFilter(token);
        },
      },
    } as ChartConfiguration;
  }

  function buildBar(labels: (string | Date)[], values: number[], field: string, horizontal = false) {
    return {
      type: "bar",
      data: {
        labels,
        datasets: [
          {
            label: field,
            data: values,
            backgroundColor: palette(values.length),
          },
        ],
      },
      options: {
        ...baseOptions,
        indexAxis: horizontal ? "y" : "x",
        onClick: (evt, elements) => {
          const token = termFromBar(elements, field);
          if (token) addFilter(token);
        },
      },
    } as ChartConfiguration;
  }

  function termFromBar(elements: any, field: string): string | undefined {
    if (!elements || elements.length === 0) return undefined;
    const label = (elements[0].element as any).$context.label;
    return `${field}:"${label}"`;
  }

  function pieTerm(elements: any, values: string[], field: string): string | undefined {
    if (!elements || !elements.length) return undefined;
    const idx = elements[0].index;
    const value = values[idx];
    return `${field}:${value}`;
  }

  function renderCharts() {
    const updated: Record<string, Chart> = {};
    chartDefinitions().forEach((definition) => {
      const ref = chartRefs[definition.key];
      if (!ref) return;
      const existing = chartRegistry()[definition.key];
      if (existing) {
        existing.destroy();
      }
      const config = definition.buildConfig(renderSeed());
      const chart = new Chart(ref, config);
      updated[definition.key] = chart;
    });
    setChartRegistry(updated);
  }

  function addFilter(fragment: string) {
    const tokens = (searchParams.q || "").split(" ").filter((t) => t.trim().length > 0);
    if (!tokens.includes(fragment)) {
      tokens.push(fragment);
    }
    setSearchParams({ ...searchParams, q: tokens.join(" ") });
    setRenderSeed((v) => v + 1);
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
    setRenderSeed((v) => v + 1);
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
                      <div>{definition.title}</div>
                      <div class="d-flex align-items-center gap-2">
                        <OverlayTrigger
                          placement="left"
                          overlay={<Tooltip>{definition.description}</Tooltip>}
                        >
                          <Button size="sm" variant="outline-secondary">
                            i
                          </Button>
                        </OverlayTrigger>
                        <Button size="sm" variant="outline-primary" onClick={() => setRenderSeed((v) => v + 1)}>
                          ↻
                        </Button>
                        <Button size="sm" variant="outline-secondary" onClick={() => addFilter(`${definition.key}:*`)}>
                          Показать PCAP…
                        </Button>
                      </div>
                    </Card.Header>
                    <Card.Body>
                      <div class="chart-container" style="height: 240px;">
                        <canvas ref={(el) => (chartRefs[definition.key] = el || undefined)} />
                      </div>
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
