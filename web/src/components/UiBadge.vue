<script setup lang="ts">
withDefaults(defineProps<{ tone?: 'green' | 'gray' | 'amber' | 'red' | 'sky'; dot?: boolean }>(), {
  tone: 'gray',
  dot: false,
})
</script>

<template>
  <span
    class="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap"
    :class="{
      'bg-emerald-50 text-emerald-800 ring-1 ring-emerald-600/20 dark:bg-emerald-500/10 dark:text-emerald-300': tone === 'green',
      'bg-slate-100 text-slate-700 ring-1 ring-slate-500/20 dark:bg-slate-700/50 dark:text-slate-300': tone === 'gray',
      'bg-amber-50 text-amber-800 ring-1 ring-amber-600/25 dark:bg-amber-500/10 dark:text-amber-300': tone === 'amber',
      'bg-rose-50 text-rose-800 ring-1 ring-rose-600/20 dark:bg-rose-500/10 dark:text-rose-300': tone === 'red',
      'bg-sky-50 text-sky-800 ring-1 ring-sky-600/20 dark:bg-sky-500/10 dark:text-sky-300': tone === 'sky',
    }"
  >
    <span
      v-if="dot"
      class="h-1.5 w-1.5 rounded-full"
      :class="{
        'bg-emerald-500': tone === 'green',
        'bg-slate-400': tone === 'gray',
        'bg-amber-500': tone === 'amber',
        'bg-rose-500': tone === 'red',
        'bg-sky-500': tone === 'sky',
      }"
    />
    <slot />
  </span>
</template>
