<script setup lang="ts">
import { computed, useId } from 'vue'

import UiHelp from './UiHelp.vue'

const model = defineModel<string | number>({ required: true })

const props = withDefaults(
  defineProps<{
    label: string
    type?: string
    error?: string
    // a short line under the field, for what's needed while typing
    helper?: string
    // what the field is for, behind a (?) next to its label
    help?: string
    placeholder?: string
    autocomplete?: string
    disabled?: boolean
    optional?: boolean
    mono?: boolean
  }>(),
  { type: 'text' },
)

const id = useId()
const describedBy = computed(
  () => [props.error || props.helper ? `${id}-help` : '', props.help ? `${id}-about` : ''].filter(Boolean).join(' ') || undefined,
)
</script>

<template>
  <div>
    <div class="mb-1.5 flex items-center gap-1.5">
      <label :for="id" class="block text-sm font-medium text-slate-800 dark:text-slate-200">
        {{ label }}
        <span v-if="optional" class="font-normal text-slate-500 dark:text-slate-400">(optional)</span>
      </label>
      <UiHelp v-if="help" :text="help" :label="label" />
    </div>
    <input
      :id="id"
      v-model="model"
      :type="type"
      :placeholder="placeholder"
      :autocomplete="autocomplete"
      :disabled="disabled"
      :aria-invalid="Boolean(error)"
      :aria-describedby="describedBy"
      class="block w-full rounded-md border bg-white px-3 py-2 text-sm text-slate-900 shadow-sm outline-none placeholder:text-slate-400 focus:ring-2 disabled:bg-slate-100 disabled:text-slate-500 dark:bg-slate-900 dark:text-slate-100 dark:disabled:bg-slate-800"
      :class="[
        error
          ? 'border-rose-500 focus:border-rose-500 focus:ring-rose-500/30'
          : 'border-slate-300 focus:border-sky-600 focus:ring-sky-600/25 dark:border-slate-600',
        { 'font-mono': mono },
      ]"
    />
    <p v-if="error" :id="id + '-help'" class="mt-1.5 text-sm text-rose-700 dark:text-rose-400">{{ error }}</p>
    <p v-else-if="helper" :id="id + '-help'" class="mt-1.5 text-sm text-slate-500 dark:text-slate-400">{{ helper }}</p>
    <span v-if="help" :id="id + '-about'" class="sr-only">{{ help }}</span>
  </div>
</template>
