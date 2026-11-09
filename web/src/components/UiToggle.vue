<script setup lang="ts">
import { useId } from 'vue'

const model = defineModel<boolean>({ required: true })
defineProps<{ label: string; description?: string; disabled?: boolean }>()
const id = useId()
</script>

<template>
  <div class="flex items-start gap-3">
    <button
      :id="id"
      type="button"
      role="switch"
      :aria-checked="model"
      :aria-describedby="description ? id + '-description' : undefined"
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
      <label :for="id" class="text-sm font-medium text-slate-800 dark:text-slate-200">{{ label }}</label>
      <p v-if="description" :id="id + '-description'" class="text-sm text-slate-500 dark:text-slate-400">
        {{ description }}
      </p>
    </div>
  </div>
</template>
