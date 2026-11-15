<script setup lang="ts">
// A state shown as a colored dot and its text, without a frame: it reads as information, not as a button. hint: a
// line under it, smaller.
withDefaults(defineProps<{ tone?: 'green' | 'gray' | 'amber' | 'red' | 'sky'; hint?: string }>(), {
  tone: 'gray',
  hint: '',
})
</script>

<template>
  <span class="inline-flex flex-col">
    <span class="inline-flex items-center gap-2 whitespace-nowrap text-slate-700 dark:text-slate-200">
      <span
        class="h-2 w-2 shrink-0 rounded-full"
        aria-hidden="true"
        :class="{
          'bg-emerald-500': tone === 'green',
          'bg-slate-400 dark:bg-slate-500': tone === 'gray',
          'bg-amber-500': tone === 'amber',
          'bg-rose-500': tone === 'red',
          'bg-sky-500': tone === 'sky',
        }"
      />
      <slot />
    </span>
    <span v-if="hint" class="mt-0.5 pl-4 text-xs text-slate-500 dark:text-slate-400">{{ hint }}</span>
  </span>
</template>
