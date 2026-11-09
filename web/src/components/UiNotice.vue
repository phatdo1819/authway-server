<script setup lang="ts">
import AppIcon from './AppIcon.vue'

withDefaults(defineProps<{ tone?: 'info' | 'warning' | 'error'; title?: string }>(), { tone: 'info' })
</script>

<template>
  <div
    class="flex gap-3 rounded-lg p-3.5 text-sm"
    :class="{
      'bg-sky-50 text-sky-900 dark:bg-sky-500/10 dark:text-sky-200': tone === 'info',
      'bg-amber-50 text-amber-900 dark:bg-amber-500/10 dark:text-amber-200': tone === 'warning',
      'bg-rose-50 text-rose-900 dark:bg-rose-500/10 dark:text-rose-200': tone === 'error',
    }"
    :role="tone === 'error' ? 'alert' : undefined"
  >
    <AppIcon :name="tone === 'info' ? 'shield' : 'alert'" :size="20" />
    <div class="min-w-0">
      <p v-if="title" class="font-semibold">{{ title }}</p>
      <div :class="{ 'mt-0.5': title }"><slot /></div>
    </div>
  </div>
</template>
