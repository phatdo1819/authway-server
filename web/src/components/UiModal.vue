<script lang="ts">
// the dialogs open, the last on top: Escape closes only that one, not a dialog or a drawer under it
const stack: symbol[] = []
</script>

<script setup lang="ts">
import { nextTick, onBeforeUnmount, ref, watch } from 'vue'

const props = withDefaults(defineProps<{ open: boolean; title: string; wide?: boolean }>(), { wide: false })
const emit = defineEmits<{ close: [] }>()
const me = Symbol()
const dialog = ref<HTMLElement | null>(null)
// what had the focus before: it gets it back when the dialog closes
let before: HTMLElement | null = null

// on the window, before the drawers, which listen on the document
function onKey(event: KeyboardEvent) {
  if (event.key === 'Escape' && stack[stack.length - 1] === me) {
    event.stopImmediatePropagation()
    emit('close')
  }
}
function leave() {
  window.removeEventListener('keydown', onKey, true)
  const at = stack.indexOf(me)
  if (at >= 0) {
    stack.splice(at, 1)
    before?.focus()
    before = null
  }
}
watch(
  () => props.open,
  async (open) => {
    if (!open) {
      leave()
      return
    }
    stack.push(me)
    window.addEventListener('keydown', onKey, true)
    before = document.activeElement instanceof HTMLElement ? document.activeElement : null
    await nextTick()
    dialog.value?.focus()
  },
  { immediate: true },
)
onBeforeUnmount(leave)
</script>

<template>
  <Teleport to="body">
    <Transition
      enter-active-class="transition-opacity duration-150"
      enter-from-class="opacity-0"
      leave-active-class="transition-opacity duration-100"
      leave-to-class="opacity-0"
    >
      <div
        v-if="open"
        class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 p-4 dark:bg-black/60"
        @click.self="emit('close')"
      >
        <div
          ref="dialog"
          role="dialog"
          aria-modal="true"
          :aria-label="title"
          tabindex="-1"
          class="max-h-full w-full overflow-y-auto rounded-xl bg-white shadow-2xl outline-none dark:bg-slate-900"
          :class="wide ? 'max-w-2xl' : 'max-w-md'"
        >
          <div class="px-6 pt-5 pb-4">
            <h2 class="text-lg font-semibold">{{ title }}</h2>
            <div class="mt-3 text-sm text-slate-600 dark:text-slate-300">
              <slot />
            </div>
          </div>
          <div
            v-if="$slots.footer"
            class="flex justify-end gap-3 rounded-b-xl bg-slate-50 px-6 py-4 dark:bg-slate-800/60"
          >
            <slot name="footer" />
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
