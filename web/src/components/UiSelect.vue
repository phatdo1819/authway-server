<script setup lang="ts" generic="T extends string | number">
import { useId } from 'vue'

const model = defineModel<T>({ required: true })
defineProps<{
  label: string
  options: { value: T; label: string }[]
  error?: string
  helper?: string
  disabled?: boolean
}>()
const id = useId()
</script>

<template>
  <div>
    <label :for="id" class="mb-1.5 block text-sm font-medium text-slate-800 dark:text-slate-200">{{ label }}</label>
    <select
      :id="id"
      v-model="model"
      :disabled="disabled"
      :aria-invalid="Boolean(error)"
      class="block w-full rounded-md border bg-white px-3 py-2 text-sm text-slate-900 shadow-sm outline-none focus:ring-2 disabled:bg-slate-100 dark:bg-slate-900 dark:text-slate-100"
      :class="
        error
          ? 'border-rose-500 focus:ring-rose-500/30'
          : 'border-slate-300 focus:border-sky-600 focus:ring-sky-600/25 dark:border-slate-600'
      "
    >
      <option v-for="option in options" :key="option.value" :value="option.value">{{ option.label }}</option>
    </select>
    <p v-if="error" class="mt-1.5 text-sm text-rose-700 dark:text-rose-400">{{ error }}</p>
    <p v-else-if="helper" class="mt-1.5 text-sm text-slate-500 dark:text-slate-400">{{ helper }}</p>
  </div>
</template>
