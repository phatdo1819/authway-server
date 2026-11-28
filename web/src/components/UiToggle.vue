<script setup lang="ts">
import { computed, useId } from 'vue'

import UiHelp from './UiHelp.vue'

const model = defineModel<boolean>({ required: true })
// description: a line under the label, always shown; help: what the switch does, behind a (?) next to it
const props = defineProps<{ label: string; description?: string; help?: string; disabled?: boolean }>()
const id = useId()
const describedBy = computed(
  () => [props.description ? `${id}-description` : '', props.help ? `${id}-about` : ''].filter(Boolean).join(' ') || undefined,
)
</script>

<template>
  <div class="flex items-start gap-3">
    <button
      :id="id"
      type="button"
      role="switch"
      :aria-checked="model"
      :aria-describedby="describedBy"
      :disabled="disabled"
      class="relative mt-0.5 inline-flex h-6 w-11 shrink-0 rounded-full transition focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-sky-600 disabled:opacity-60"
      :class="model ? 'bg-sky-700 dark:bg-sky-500' : 'bg-slate-300 dark:bg-slate-600'"
      @click="model = !model"
    >
      <span
        class="absolute top-0.5 left-0.5 h-5 w-5 rounded-full bg-white shadow transition"
        :class="model ? 'translate-x-5' : 'translate-x-0'"
      />
    </button>
    <div>
      <div class="flex min-h-6 items-center gap-1.5">
        <label :for="id" class="text-sm font-medium text-slate-800 dark:text-slate-200">{{ label }}</label>
        <UiHelp v-if="help" :text="help" :label="label" />
      </div>
      <p v-if="description" :id="id + '-description'" class="text-sm text-slate-500 dark:text-slate-400">
        {{ description }}
      </p>
      <span v-if="help" :id="id + '-about'" class="sr-only">{{ help }}</span>
    </div>
  </div>
</template>
