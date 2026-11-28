<script lang="ts">
// the help panels open: Escape closes them first, not the dialog or the drawer under them
let openCount = 0
export function helpOpen(): boolean {
  return openCount > 0
}
</script>

<script setup lang="ts">
import { nextTick, onBeforeUnmount, ref, useId, watch } from 'vue'

import AppIcon from './AppIcon.vue'

// A (?) next to a label: a click opens its help in a small panel, and a click anywhere else, or Escape, closes it.
// Screen readers get the text as the description of the field (see UiInput): this is for the eyes.
const props = defineProps<{ text: string; label: string }>()
const open = ref(false)
const button = ref<HTMLButtonElement | null>(null)
const panel = ref<HTMLElement | null>(null)
const id = useId()
const place = ref({ top: 0, left: 0, width: 320 })

// under the (?), or above it without room below; inside the window, 16 px from its edges
function position() {
  const rect = button.value?.getBoundingClientRect()
  if (!rect) {
    return
  }
  const gutter = 16
  const width = Math.min(320, window.innerWidth - 2 * gutter)
  const left = Math.max(gutter, Math.min(rect.left - 12, window.innerWidth - gutter - width))
  const height = panel.value?.offsetHeight ?? 0
  let top = rect.bottom + 6
  if (height > 0 && top + height > window.innerHeight - gutter && rect.top - 6 - height >= gutter) {
    top = rect.top - 6 - height
  }
  place.value = { top, left, width }
}
async function toggle() {
  open.value = !open.value
  if (open.value) {
    position()
    // with its height
    await nextTick()
    position()
  }
}
function close(focus: boolean) {
  open.value = false
  if (focus) {
    button.value?.focus()
  }
}
function onPointer(event: PointerEvent) {
  const target = event.target as Node
  if (!button.value?.contains(target) && !panel.value?.contains(target)) {
    close(false)
  }
}
function onKey(event: KeyboardEvent) {
  if (event.key === 'Escape') {
    event.stopImmediatePropagation()
    close(true)
  }
}
function listen(on: boolean) {
  const method = on ? 'addEventListener' : 'removeEventListener'
  document[method]('pointerdown', onPointer as EventListener, true)
  window[method]('keydown', onKey as EventListener, true)
  // it follows its (?) when the page or the drawer scrolls
  window[method]('scroll', position, true)
  window[method]('resize', position)
}
watch(open, (now) => {
  openCount += now ? 1 : -1
  listen(now)
})
onBeforeUnmount(() => {
  if (open.value) {
    openCount--
    listen(false)
  }
})
</script>

<template>
  <button
    ref="button"
    type="button"
    class="inline-flex shrink-0 items-center justify-center rounded-full align-middle text-slate-400 hover:text-sky-700 focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-sky-600 dark:text-slate-500 dark:hover:text-sky-400"
    :class="open ? 'text-sky-700 dark:text-sky-400' : ''"
    :aria-label="`About ${props.label}`"
    :aria-expanded="open"
    :aria-controls="open ? id : undefined"
    @click.prevent.stop="toggle"
  >
    <AppIcon name="help" :size="16" />
  </button>
  <Teleport to="body">
    <div
      v-if="open"
      :id="id"
      ref="panel"
      class="fixed z-[70] rounded-lg border border-slate-200 bg-white p-3 text-sm leading-relaxed font-normal text-slate-700 shadow-lg dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
      :style="{ top: `${place.top}px`, left: `${place.left}px`, width: `${place.width}px` }"
    >
      {{ props.text }}
    </div>
  </Teleport>
</template>
