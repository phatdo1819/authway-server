<script setup lang="ts" generic="T extends string | number">
import { computed, useId } from 'vue'

import UiHelp from './UiHelp.vue'

const model = defineModel<T>({ required: true })
const props = defineProps<{
  label: string
  options: { value: T; label: string }[]
  error?: string
  helper?: string
  // what the field is for, behind a (?) next to its label
  help?: string
  disabled?: boolean
}>()
const id = useId()
const describedBy = computed(
  () => [props.error || props.helper ? `${id}-help` : '', props.help ? `${id}-about` : ''].filter(Boolean).join(' ') || undefined,
)
</script>

<template>
  <div>
    <div class="mb-1.5 flex items-center gap-1.5">
      <label :for="id" class="block text-sm font-medium text-slate-800 dark:text-slate-200">{{ label }}</label>
      <UiHelp v-if="help" :text="help" :label="label" />
    </div>
    <select
      :id="id"
      v-model="model"
      :disabled="disabled"
      :aria-invalid="Boolean(error)"
      :aria-describedby="describedBy"
      class="block w-full rounded-md border bg-white px-3 py-2 text-sm text-slate-900 shadow-sm outline-none focus:ring-2 disabled:bg-slate-100 dark:bg-slate-900 dark:text-slate-100"
      :class="
        error
          ? 'border-rose-500 focus:ring-rose-500/30'
          : 'border-slate-300 focus:border-sky-600 focus:ring-sky-600/25 dark:border-slate-600'
      "
    >
      <option v-for="option in options" :key="option.value" :value="option.value">{{ option.label }}</option>
    </select>
    <p v-if="error" :id="id + '-help'" class="mt-1.5 text-sm text-rose-700 dark:text-rose-400">{{ error }}</p>
    <p v-else-if="helper" :id="id + '-help'" class="mt-1.5 text-sm text-slate-500 dark:text-slate-400">{{ helper }}</p>
    <span v-if="help" :id="id + '-about'" class="sr-only">{{ help }}</span>
  </div>
</template>
