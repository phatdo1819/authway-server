<script setup lang="ts">
import { nextTick, onBeforeUnmount, ref } from 'vue'

import AppIcon, { type IconName } from './AppIcon.vue'

export interface MenuItem {
  label: string
  icon?: IconName
  danger?: boolean
  disabled?: boolean
  action: () => void
}

// the actions of a row, behind a ⋮ button. The menu opens on the page itself, over everything: inside a table that
// scrolls it was cut by its edges and made it scroll
const props = defineProps<{ items: MenuItem[]; label: string }>()
const open = ref(false)
const button = ref<HTMLButtonElement | null>(null)
const menu = ref<HTMLElement | null>(null)
const place = ref({ top: 0, left: 0 })
// w-56
const width = 224
const margin = 8

// under the button, its right edges aligned; above it when there's no room under it; always in the window
function position() {
  const rect = button.value?.getBoundingClientRect()
  if (!rect) {
    return
  }
  if (rect.bottom < 0 || rect.top > window.innerHeight) {
    close()
    return
  }
  const height = menu.value?.offsetHeight ?? props.items.length * 40 + 10
  const below = window.innerHeight - rect.bottom - margin
  const above = rect.top - margin
  const up = below < height + 4 && above > below
  const top = up ? rect.top - height - 4 : Math.min(rect.bottom + 4, window.innerHeight - height - margin)
  const left = Math.min(Math.max(margin, rect.right - width), window.innerWidth - width - margin)
  place.value = { top: Math.max(margin, top), left }
}

function close() {
  open.value = false
  document.removeEventListener('click', outside, true)
  document.removeEventListener('keydown', onKey)
  window.removeEventListener('scroll', position, true)
  window.removeEventListener('resize', position)
}

function outside(event: MouseEvent) {
  const target = event.target as Node
  if (!button.value?.contains(target) && !menu.value?.contains(target)) {
    close()
  }
}

function onKey(event: KeyboardEvent) {
  const items = [...(menu.value?.querySelectorAll<HTMLElement>('[role="menuitem"]:not([disabled])') ?? [])]
  const index = items.indexOf(document.activeElement as HTMLElement)
  if (event.key === 'Escape' || event.key === 'Tab') {
    // the menu is at the end of the page: Tab goes on from the button, as if the menu were next to it
    close()
    button.value?.focus()
  } else if (event.key === 'ArrowDown') {
    event.preventDefault()
    items[(index + 1) % items.length]?.focus({ preventScroll: true })
  } else if (event.key === 'ArrowUp') {
    event.preventDefault()
    items[(index - 1 + items.length) % items.length]?.focus({ preventScroll: true })
  }
}

async function toggle() {
  if (open.value) {
    close()
    return
  }
  position()
  open.value = true
  document.addEventListener('click', outside, true)
  document.addEventListener('keydown', onKey)
  window.addEventListener('scroll', position, true)
  window.addEventListener('resize', position)
  await nextTick()
  // now that it has its real height
  position()
  menu.value?.querySelector<HTMLElement>('[role="menuitem"]:not([disabled])')?.focus({ preventScroll: true })
}

function run(index: number) {
  close()
  props.items[index].action()
}

onBeforeUnmount(close)
</script>

<template>
  <div class="inline-block text-left">
    <button
      ref="button"
      type="button"
      class="rounded-md p-1.5 text-slate-500 hover:bg-slate-100 hover:text-slate-800 dark:hover:bg-slate-800 dark:hover:text-slate-100"
      :aria-label="label"
      aria-haspopup="menu"
      :aria-expanded="open"
      @click="toggle"
    >
      <AppIcon name="dots" />
    </button>
    <Teleport to="body">
      <div
        v-if="open"
        ref="menu"
        role="menu"
        :aria-label="label"
        class="fixed z-50 w-56 rounded-lg border border-slate-200 bg-white py-1 shadow-lg dark:border-slate-700 dark:bg-slate-800"
        :style="{ top: `${place.top}px`, left: `${place.left}px` }"
      >
        <button
          v-for="(item, index) in items"
          :key="item.label"
          type="button"
          role="menuitem"
          :disabled="item.disabled"
          class="flex w-full items-center gap-2.5 px-3 py-2 text-left text-sm focus:outline-none disabled:opacity-50"
          :class="
            item.danger
              ? 'text-rose-700 hover:bg-rose-50 focus:bg-rose-50 dark:text-rose-400 dark:hover:bg-rose-500/10 dark:focus:bg-rose-500/10'
              : 'text-slate-700 hover:bg-slate-100 focus:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-700 dark:focus:bg-slate-700'
          "
          @click="run(index)"
        >
          <AppIcon v-if="item.icon" :name="item.icon" :size="18" />
          {{ item.label }}
        </button>
      </div>
    </Teleport>
  </div>
</template>
