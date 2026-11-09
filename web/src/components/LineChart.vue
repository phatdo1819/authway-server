<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'

import { formatBytes, formatPercent, formatRate } from '../format'

// A line chart of a history: one axis, a line for each series (the first blue with a wash under it, the second
// orange), a crosshair with every value under the pointer or the arrow keys, and a table of the values.
export interface ChartSeries {
  name: string
  values: number[]
}

const props = defineProps<{
  // what the chart shows, for the screen readers and the table
  label: string
  times: number[]
  series: ChartSeries[]
  // the time on the axis, Unix seconds, and the seconds between two points: a longer gap breaks the line
  start: number
  end: number
  step: number
  unit: 'percent' | 'bytes' | 'rate'
  // the top of the axis for the bytes: the memory of the host. The percents go to 100, the rates fit the values
  max?: number
}>()

const height = 184
const top = 16
const bottom = 22
const plotHeight = height - top - bottom
const colors = ['var(--chart-1)', 'var(--chart-2)']

const box = ref<HTMLDivElement>()
const width = ref(640)
let observer: ResizeObserver | undefined
onMounted(() => {
  observer = new ResizeObserver((entries) => {
    width.value = Math.max(240, Math.round(entries[0].contentRect.width))
  })
  if (box.value) {
    observer.observe(box.value)
  }
})
onBeforeUnmount(() => observer?.disconnect())

function format(value: number): string {
  if (props.unit === 'percent') {
    return formatPercent(value)
  }
  return props.unit === 'bytes' ? formatBytes(value) : formatRate(value)
}

// the points in the time of the axis
const first = computed(() => {
  const index = props.times.findIndex((t) => t >= props.start)
  return index < 0 ? props.times.length : index
})
const visible = computed(() => props.times.length - first.value)

function highest(): number {
  let value = 0
  for (const series of props.series) {
    for (let index = first.value; index < series.values.length; index++) {
      value = Math.max(value, series.values[index])
    }
  }
  return value
}

// 1, 2 or 5 times a power of ten
function niceStep(raw: number): number {
  const power = Math.pow(10, Math.floor(Math.log10(raw)))
  const fraction = raw / power
  return (fraction <= 1 ? 1 : fraction <= 2 ? 2 : fraction <= 5 ? 5 : 10) * power
}

// the top of the axis and its lines, in the unit of the values
const axis = computed(() => {
  if (props.unit === 'percent') {
    return { top: 100, ticks: [0, 25, 50, 75, 100] }
  }
  if (props.unit === 'bytes') {
    const topValue = props.max || Math.max(1024, highest())
    const unit = Math.pow(1024, Math.max(0, Math.floor(Math.log(topValue) / Math.log(1024))))
    const step = niceStep(topValue / unit / 4) * unit
    const ticks: number[] = []
    for (let value = 0; value < topValue - step * 0.35; value += step) {
      ticks.push(value)
    }
    ticks.push(topValue)
    return { top: topValue, ticks }
  }
  // in bits per second, 1 kbit/s at least
  const bits = Math.max(1000, highest() * 8)
  const step = niceStep(bits / 4)
  const topBits = Math.ceil(bits / step) * step
  const ticks: number[] = []
  for (let value = 0; value <= topBits + step / 2; value += step) {
    ticks.push(value / 8)
  }
  return { top: topBits / 8, ticks }
})

function x(t: number): number {
  return ((t - props.start) / Math.max(1, props.end - props.start)) * width.value
}

function y(value: number): number {
  return top + plotHeight - (Math.min(Math.max(value, 0), axis.value.top) / axis.value.top) * plotHeight
}

const paths = computed(() =>
  props.series.map((series) => {
    let line = ''
    let area = ''
    let lastX = ''
    const baseline = y(0).toFixed(1)
    for (let index = first.value; index < props.times.length; index++) {
      const px = x(props.times[index]).toFixed(1)
      const py = y(series.values[index] ?? 0).toFixed(1)
      const gap = index === first.value || props.times[index] - props.times[index - 1] > 3 * props.step
      if (gap) {
        if (lastX) {
          area += `L${lastX},${baseline}Z`
        }
        line += `M${px},${py}`
        area += `M${px},${baseline}L${px},${py}`
      } else {
        line += `L${px},${py}`
        area += `L${px},${py}`
      }
      lastX = px
    }
    if (lastX) {
      area += `L${lastX},${baseline}Z`
    }
    return { line, area }
  }),
)

const xTicks = computed(() => {
  const span = props.end - props.start
  const step = span <= 900 ? 300 : span <= 3600 ? 900 : span <= 21600 ? 3600 : 14400
  // on the hours of this computer
  const offset = -new Date(props.end * 1000).getTimezoneOffset() * 60
  const ticks: { x: number; label: string }[] = []
  for (let t = Math.ceil((props.start + offset) / step) * step - offset; t <= props.end; t += step) {
    const px = x(t)
    // half a label from the edges: 09:15 PM is about 50 px wide
    if (px >= 30 && px <= width.value - 30) {
      ticks.push({ x: px, label: new Date(t * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) })
    }
  }
  return ticks
})

function timeText(t: number): string {
  const options: Intl.DateTimeFormatOptions =
    props.step < 60 ? { hour: '2-digit', minute: '2-digit', second: '2-digit' } : { hour: '2-digit', minute: '2-digit' }
  const day = new Date(t * 1000)
  const today = new Date()
  const text = day.toLocaleTimeString([], options)
  return day.toDateString() === today.toDateString() ? text : `${day.toLocaleDateString([], { day: 'numeric', month: 'short' })} ${text}`
}

// the point under the pointer, by its time: it stays while new points come
const hoverAt = ref(0)
const keyboard = ref('')

function nearest(t: number): number {
  let low = first.value
  let high = props.times.length - 1
  if (high < low) {
    return -1
  }
  while (low < high) {
    const middle = (low + high) >> 1
    if (props.times[middle] < t) {
      low = middle + 1
    } else {
      high = middle
    }
  }
  if (low > first.value && t - props.times[low - 1] < props.times[low] - t) {
    return low - 1
  }
  return low
}

const hover = computed(() => (hoverAt.value ? nearest(hoverAt.value) : -1))

function readout(index: number): string {
  return `${timeText(props.times[index])}: ${props.series.map((series) => `${series.name} ${format(series.values[index])}`).join(', ')}`
}

function move(event: PointerEvent) {
  const rect = (event.currentTarget as Element).getBoundingClientRect()
  hoverAt.value = props.start + ((event.clientX - rect.left) / rect.width) * (props.end - props.start)
}

function key(event: KeyboardEvent) {
  const last = props.times.length - 1
  if (last < first.value) {
    return
  }
  let index = hover.value < 0 ? last : hover.value
  const page = Math.max(1, Math.round(visible.value / 10))
  switch (event.key) {
    case 'ArrowLeft':
      index = Math.max(first.value, index - 1)
      break
    case 'ArrowRight':
      index = Math.min(last, index + 1)
      break
    case 'PageUp':
      index = Math.max(first.value, index - page)
      break
    case 'PageDown':
      index = Math.min(last, index + page)
      break
    case 'Home':
      index = first.value
      break
    case 'End':
      index = last
      break
    case 'Escape':
      hoverAt.value = 0
      return
    default:
      return
  }
  event.preventDefault()
  hoverAt.value = props.times[index]
  keyboard.value = readout(index)
}

const summary = computed(() => {
  const last = props.times.length - 1
  if (last < first.value) {
    return `${props.label}: no values yet.`
  }
  const now = props.series.map((series) => `${series.name} ${format(series.values[last])}`).join(', ')
  return `${props.label}. Now: ${now}. Highest: ${format(highest())}. Arrow keys move along the time.`
})

// the table of the values: 60 rows at most, the newest first
const tableOpen = ref(false)
const rows = computed(() => {
  if (!tableOpen.value) {
    return []
  }
  const every = Math.max(1, Math.ceil(visible.value / 60))
  const list: number[] = []
  for (let index = props.times.length - 1; index >= first.value; index -= every) {
    list.push(index)
  }
  return list
})
</script>

<template>
  <div>
    <ul v-if="series.length > 1" class="mb-2 flex flex-wrap gap-x-5 gap-y-1 text-sm">
      <li v-for="(entry, index) in series" :key="entry.name" class="flex items-center gap-2">
        <svg width="16" height="8" aria-hidden="true">
          <line x1="1" y1="4" x2="15" y2="4" :stroke="colors[index]" stroke-width="2" stroke-linecap="round" />
        </svg>
        <span class="text-slate-600 dark:text-slate-300">{{ entry.name }}</span>
        <span v-if="visible" class="font-medium text-slate-900 tabular-nums dark:text-slate-100">
          {{ format(entry.values[entry.values.length - 1]) }}
        </span>
      </li>
    </ul>
    <div
      ref="box"
      class="relative overflow-hidden rounded-md outline-none focus-visible:ring-2 focus-visible:ring-sky-600/40"
      tabindex="0"
      role="group"
      :aria-label="summary"
      @pointermove="move"
      @pointerleave="hoverAt = 0"
      @keydown="key"
      @blur="hoverAt = 0"
    >
      <svg :width="width" :height="height" class="block touch-pan-y" aria-hidden="true">
        <g>
          <line
            v-for="tick in axis.ticks"
            :key="'grid' + tick"
            x1="0"
            :x2="width"
            :y1="y(tick)"
            :y2="y(tick)"
            :stroke="tick === 0 ? 'var(--chart-axis)' : 'var(--chart-grid)'"
            stroke-width="1"
            shape-rendering="crispEdges"
          />
        </g>
        <path v-if="paths[0]" :d="paths[0].area" :fill="colors[0]" fill-opacity="0.1" />
        <path
          v-for="(path, index) in paths"
          :key="'line' + index"
          :d="path.line"
          fill="none"
          :stroke="colors[index]"
          stroke-width="2"
          stroke-linejoin="round"
          stroke-linecap="round"
        />
        <g class="fill-slate-500 text-[11px] dark:fill-slate-400" style="paint-order: stroke" stroke="var(--chart-surface)" stroke-width="3">
          <text v-for="tick in axis.ticks" :key="'label' + tick" x="2" :y="y(tick) - 4">{{ format(tick) }}</text>
          <text v-for="tick in xTicks" :key="'time' + tick.x" :x="tick.x" :y="height - 6" text-anchor="middle">{{ tick.label }}</text>
        </g>
        <g v-if="hover >= 0">
          <line
            :x1="x(times[hover])"
            :x2="x(times[hover])"
            :y1="top"
            :y2="top + plotHeight"
            stroke="var(--chart-axis)"
            stroke-width="1"
            shape-rendering="crispEdges"
          />
          <circle
            v-for="(entry, index) in series"
            :key="'dot' + index"
            :cx="x(times[hover])"
            :cy="y(entry.values[hover])"
            r="4"
            :fill="colors[index]"
            stroke="var(--chart-surface)"
            stroke-width="2"
          />
        </g>
      </svg>
      <p v-if="!visible" class="absolute inset-0 flex items-center justify-center text-sm text-slate-500 dark:text-slate-400">
        No values yet: the first ones come within 10 seconds.
      </p>
      <div
        v-if="hover >= 0"
        class="pointer-events-none absolute top-2 z-10 min-w-36 rounded-md border border-slate-200 bg-white px-3 py-2 text-sm shadow-lg dark:border-slate-700 dark:bg-slate-800"
        :style="x(times[hover]) > width / 2 ? { right: `${width - x(times[hover]) + 12}px` } : { left: `${x(times[hover]) + 12}px` }"
        aria-hidden="true"
      >
        <p class="text-xs text-slate-500 dark:text-slate-400">{{ timeText(times[hover]) }}</p>
        <p v-for="(entry, index) in series" :key="'tip' + index" class="mt-1 flex items-center gap-2 whitespace-nowrap">
          <svg width="12" height="8" aria-hidden="true">
            <line x1="1" y1="4" x2="11" y2="4" :stroke="colors[index]" stroke-width="2" stroke-linecap="round" />
          </svg>
          <span class="font-semibold text-slate-900 tabular-nums dark:text-slate-100">{{ format(entry.values[hover]) }}</span>
          <span class="text-slate-500 dark:text-slate-400">{{ entry.name }}</span>
        </p>
      </div>
      <p class="sr-only" aria-live="polite">{{ keyboard }}</p>
    </div>
    <details class="mt-2" @toggle="tableOpen = ($event.target as HTMLDetailsElement).open">
      <summary class="cursor-pointer text-xs font-medium text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200">
        Show the values
      </summary>
      <div class="mt-2 max-h-72 overflow-auto rounded-md border border-slate-200 dark:border-slate-800">
        <table class="min-w-full text-xs">
          <caption class="sr-only">{{ label }}</caption>
          <thead class="sticky top-0 bg-slate-50 text-left text-slate-500 dark:bg-slate-800 dark:text-slate-400">
            <tr>
              <th scope="col" class="px-3 py-1.5 font-medium">Time</th>
              <th v-for="entry in series" :key="'head' + entry.name" scope="col" class="px-3 py-1.5 text-right font-medium">{{ entry.name }}</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-100 tabular-nums dark:divide-slate-800">
            <tr v-for="index in rows" :key="times[index]">
              <td class="px-3 py-1 whitespace-nowrap">{{ timeText(times[index]) }}</td>
              <td v-for="entry in series" :key="'cell' + entry.name" class="px-3 py-1 text-right whitespace-nowrap">
                {{ format(entry.values[index]) }}
              </td>
            </tr>
            <tr v-if="!rows.length">
              <td :colspan="series.length + 1" class="px-3 py-2 text-slate-500">No values yet.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </details>
  </div>
</template>
