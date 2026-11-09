<script setup lang="ts">
import AppIcon, { type IconName } from './AppIcon.vue'

defineProps<{ icon: IconName; title: string; text?: string }>()
</script>

<template>
  <div class="rounded-xl border border-dashed border-slate-300 px-6 py-12 text-center dark:border-slate-700">
    <div
      class="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-sky-50 text-sky-700 dark:bg-sky-500/10 dark:text-sky-300"
    >
      <AppIcon :name="icon" :size="24" />
    </div>
    <h3 class="mt-4 text-base font-semibold">{{ title }}</h3>
    <p v-if="text" class="mx-auto mt-1 max-w-md text-sm text-slate-500 dark:text-slate-400">{{ text }}</p>
    <div v-if="$slots.default" class="mt-5"><slot /></div>
  </div>
</template>
