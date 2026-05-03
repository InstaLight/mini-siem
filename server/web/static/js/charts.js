(function (global) {
  "use strict";

  const SIEM = global.SIEM || (global.SIEM = {});

  const COLORS = {
    high: "#e27171",
    medium: "#d4a255",
    low: "#4ec38a",
    accent: "#6ea1ff",
    gridLine: "rgba(150, 165, 200, 0.18)",
    tickLabel: "#b3c0db",
  };

  SIEM.charts = SIEM.charts || {};

  function ensureChartJs() {
    if (typeof global.Chart === "undefined") {
      console.warn("Chart.js not loaded yet; retrying shortly");
      return false;
    }
    return true;
  }

  function createSeverityDonut(canvasId, initial) {
    if (!ensureChartJs()) return null;
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;
    const chart = new global.Chart(ctx, {
      type: "doughnut",
      data: {
        labels: ["High", "Medium", "Low"],
        datasets: [
          {
            data: [initial.high || 0, initial.medium || 0, initial.low || 0],
            backgroundColor: [COLORS.high, COLORS.medium, COLORS.low],
            borderColor: "#0b0f17",
            borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "62%",
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: COLORS.tickLabel, font: { size: 12 } },
          },
          tooltip: {
            callbacks: {
              label: (item) => `${item.label}: ${item.parsed}`,
            },
          },
        },
      },
    });
    return {
      chart,
      update(next) {
        chart.data.datasets[0].data = [next.high || 0, next.medium || 0, next.low || 0];
        chart.update("none");
      },
    };
  }

  function createActivityTimeline(canvasId, initial) {
    if (!ensureChartJs()) return null;
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;
    const chart = new global.Chart(ctx, {
      type: "line",
      data: {
        labels: (initial.buckets || []).map((b) => formatBucket(b.bucket_start)),
        datasets: [
          {
            label: "Events",
            data: (initial.buckets || []).map((b) => b.count),
            tension: 0.3,
            fill: true,
            backgroundColor: "rgba(110, 161, 255, 0.18)",
            borderColor: COLORS.accent,
            borderWidth: 2,
            pointRadius: 0,
            pointHoverRadius: 3,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { intersect: false, mode: "index" },
        plugins: { legend: { display: false } },
        scales: {
          x: {
            ticks: { color: COLORS.tickLabel, maxRotation: 0, autoSkip: true, maxTicksLimit: 8 },
            grid: { color: COLORS.gridLine },
          },
          y: {
            beginAtZero: true,
            ticks: { color: COLORS.tickLabel, precision: 0 },
            grid: { color: COLORS.gridLine },
          },
        },
      },
    });
    return {
      chart,
      update(next) {
        chart.data.labels = (next.buckets || []).map((b) => formatBucket(b.bucket_start));
        chart.data.datasets[0].data = (next.buckets || []).map((b) => b.count);
        chart.update("none");
      },
    };
  }

  function formatBucket(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  SIEM.charts.createSeverityDonut = createSeverityDonut;
  SIEM.charts.createActivityTimeline = createActivityTimeline;
})(window);
