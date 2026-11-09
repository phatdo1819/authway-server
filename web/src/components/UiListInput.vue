<script setup lang="ts">
import AppIcon from './AppIcon.vue'

// a list of short texts, one per row: networks, DNS servers
const model = defineModel<string[]>({ required: true })
defineProps<{ label: string; placeholder?: string; addLabel: string; error?: string; helper?: string }>()

function remove(index: number) {
  model.value = model.value.filter((_, i) => i !== index)
}
</script>

<template>
  <fieldset>
    <legend class="mb-1.5 block text-sm font-medium text-slate-800 dark:text-slate-200">{{ label }}</legend>
    <div class="space-y-2">
      <div v-for="(_, index) in model" :key="index" class="flex gap-2">
        <input
          v-model="model[index]"
          :placeholder="placeholder"
          :aria-label="`${label} ${index + 1}`"
          class="block w-full rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-sm shadow-sm outline-none focus:border-sky-600 focus:ring-2 focus:ring-sky-600/25 dark:border-slate-600 dark:bg-slate-900"
        />
        <button
          type="button"
          class="rounded-md px-2 text-slate-500 hover:bg-slate-100 hover:text-rose-700 dark:hover:bg-slate-800"
          :aria-label="`Remove ${model[index] || 'row'}`"
          @click="remove(index)"
        >
          <AppIcon name="trash" :size="18" />
        </button>
      </div>
    </div>
    <button
      type="button"
      class="mt-2 inline-flex items-center gap-1.5 text-sm font-medium text-sky-700 hover:text-sky-900 dark:text-sky-400 dark:hover:text-sky-300"
      @click="model = [...model, '']"
    >
      <AppIcon name="plus" :size="16" />{{ addLabel }}
    </button>
    <p v-if="error" class="mt-1.5 text-sm text-rose-700 dark:text-rose-400">{{ error }}</p>
    <p v-else-if="helper" class="mt-1.5 text-sm text-slate-500 dark:text-slate-400">{{ helper }}</p>
  </fieldset>
</template>
