<script setup lang="ts">
import { computed, ref, useId, watch } from 'vue'

import { anyAddressOf } from '../../addresses'
import UiButton from '../../components/UiButton.vue'
import UiModal from '../../components/UiModal.vue'
import UiNotice from '../../components/UiNotice.vue'
import type { RouterRoute } from '../../routing'

// NAT or routed, with a drawing of one peer and one computer of the network. routed: the mode shown first. route: the
// route of the router for the server, see routerRoute, null while the address of Authway Server isn't known
const props = defineProps<{ open: boolean; routed: boolean; route: RouterRoute | null }>()
const emit = defineEmits<{ close: [] }>()

const shown = ref(props.routed)
watch(
  () => props.open,
  (open) => {
    if (open) {
      shown.value = props.routed
    }
  },
)

// the addresses of the drawing and of the text: the ones of the server, with x for any peer and any computer, once
// the address of Authway Server in its network is known; examples until then
const real = computed(() => props.route)
const tunnel = computed(() => real.value?.tunnel ?? '10.8.0.0/24')
const lan = computed(() => real.value?.network ?? '192.168.1.0/24')
const authway = computed(() => real.value?.via ?? '192.168.1.50')
const peer = computed(() => (real.value ? anyAddressOf(real.value.tunnel, 2) : '10.8.0.5'))
const computer = computed(() => (real.value ? anyAddressOf(real.value.network, 20) : '192.168.1.20'))
// the address of Authway Server is the one of the Docker host, compose.host-routes.yaml, or of its container. With
// the example addresses, both ways show it
const throughHost = computed(() => !real.value || real.value.dockerHost)
const ownAddress = computed(() => !real.value || !real.value.dockerHost)

const id = useId()
const arrowSent = `${id}-sent`
const arrowAnswer = `${id}-answer`
const description = computed(() =>
  shown.value
    ? `The peer ${peer.value} sends traffic through the WireGuard tunnel to Authway Server, which keeps the peer's address, so the computer ${computer.value} sees ${peer.value}. Because ${peer.value} isn't on the local network, the computer sends its reply to the router, which passes it to Authway Server using the route ${tunnel.value} via ${authway.value}.`
    : `The peer ${peer.value} sends traffic through the WireGuard tunnel to Authway Server, which replaces the peer's address with its own, so the computer ${computer.value} sees ${authway.value} and replies to it directly. No router changes needed.`,
)
const modes = [
  { routed: false, label: 'NAT' },
  { routed: true, label: 'Routed' },
]
</script>

<template>
  <UiModal :open="open" title="NAT or routed mode" wide @close="emit('close')">
    <div class="space-y-4">
      <p>What the computers of the networks of a server see when its peers connect to them.</p>

      <div
        class="inline-flex rounded-lg border border-slate-200 bg-white p-0.5 dark:border-slate-700 dark:bg-slate-800"
        role="group"
        aria-label="Mode shown"
      >
        <button
          v-for="mode in modes"
          :key="mode.label"
          type="button"
          class="rounded-md px-4 py-1.5 text-sm font-medium"
          :class="
            shown === mode.routed
              ? 'bg-sky-700 text-white dark:bg-sky-500 dark:text-slate-950'
              : 'text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-700'
          "
          :aria-pressed="shown === mode.routed"
          @click="shown = mode.routed"
        >
          {{ mode.label }}
        </button>
      </div>

      <!-- the drawing keeps its size on a phone: it scrolls sideways, the text below says it all -->
      <div class="overflow-x-auto">
        <svg
          viewBox="0 0 640 250"
          class="block h-auto w-full min-w-[34rem]"
          role="img"
          :aria-labelledby="`${id}-title ${id}-desc`"
        >
          <title :id="`${id}-title`">{{ shown ? 'Routed' : 'NAT' }}: what a computer of the network sees of a peer</title>
          <desc :id="`${id}-desc`">{{ description }}</desc>
          <defs>
            <marker
              :id="arrowSent"
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="7"
              markerHeight="7"
              orient="auto-start-reverse"
            >
              <path d="M0 0L10 5L0 10z" style="fill: var(--chart-1)" />
            </marker>
            <marker
              :id="arrowAnswer"
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="7"
              markerHeight="7"
              orient="auto-start-reverse"
            >
              <path d="M0 0L10 5L0 10z" style="fill: var(--chart-2)" />
            </marker>
          </defs>

          <!-- where the peer is, and the local network -->
          <text x="72" y="30" text-anchor="middle" class="fill-slate-500 text-[12px] dark:fill-slate-400">Anywhere</text>
          <rect
            x="192"
            y="8"
            width="440"
            height="234"
            rx="14"
            stroke-dasharray="5 4"
            class="fill-slate-50 stroke-slate-300 dark:fill-slate-800/40 dark:stroke-slate-600"
          />
          <text x="208" y="30" class="fill-slate-500 text-[12px] dark:fill-slate-400">
            Local network <tspan class="font-mono">{{ lan }}</tspan>
          </text>

          <!-- the tunnel: its label hides the edge of the network under it -->
          <rect x="133" y="70" width="98" height="17" rx="3" style="fill: var(--chart-surface)" />
          <text x="182" y="82" text-anchor="middle" class="fill-slate-500 text-[12px] dark:fill-slate-400">WireGuard tunnel</text>
          <rect
            x="132"
            y="90"
            width="100"
            height="20"
            rx="10"
            class="fill-sky-50 stroke-sky-300 dark:fill-sky-950 dark:stroke-sky-700"
          />
          <line x1="140" y1="100" x2="222" y2="100" stroke-width="2" style="stroke: var(--chart-1)" :marker-end="`url(#${arrowSent})`" />
          <rect x="130" y="134" width="104" height="20" rx="10" stroke-width="1.5" style="fill: var(--chart-surface); stroke: var(--chart-1)" />
          <text x="182" y="148" text-anchor="middle" class="fill-slate-800 font-mono text-[12px] dark:fill-slate-100">
            from {{ peer }}
          </text>

          <!-- the request, from Authway Server to the computer: the address it comes from -->
          <line x1="352" y1="90" x2="496" y2="90" stroke-width="2" style="stroke: var(--chart-1)" :marker-end="`url(#${arrowSent})`" />
          <rect x="360" y="79" width="132" height="22" rx="11" stroke-width="1.5" style="fill: var(--chart-surface); stroke: var(--chart-1)" />
          <text x="426" y="94" text-anchor="middle" class="fill-slate-800 font-mono text-[12px] dark:fill-slate-100">
            from {{ shown ? peer : authway }}
          </text>

          <!-- the answer: straight back with NAT, through the router when routed -->
          <template v-if="!shown">
            <line x1="500" y1="112" x2="356" y2="112" stroke-width="2" style="stroke: var(--chart-2)" :marker-end="`url(#${arrowAnswer})`" />
            <text x="426" y="132" text-anchor="middle" class="fill-slate-600 text-[12px] dark:fill-slate-300">
              reply to <tspan class="font-mono">{{ authway }}</tspan>
            </text>
          </template>
          <template v-else>
            <path d="M560 128V203H542" fill="none" stroke-width="2" style="stroke: var(--chart-2)" :marker-end="`url(#${arrowAnswer})`" />
            <path d="M314 203H292V132" fill="none" stroke-width="2" style="stroke: var(--chart-2)" :marker-end="`url(#${arrowAnswer})`" />
            <text x="552" y="162" text-anchor="end" class="fill-slate-600 text-[12px] dark:fill-slate-300">
              reply to <tspan class="font-mono">{{ peer }}</tspan>
            </text>
          </template>

          <!-- the peer -->
          <rect x="12" y="72" width="120" height="56" rx="10" class="fill-white stroke-slate-300 dark:fill-slate-900 dark:stroke-slate-600" />
          <text x="72" y="95" text-anchor="middle" class="fill-slate-800 text-[13px] font-semibold dark:fill-slate-100">Peer</text>
          <text x="72" y="114" text-anchor="middle" class="fill-slate-600 font-mono text-[12px] dark:fill-slate-300">{{ peer }}</text>

          <!-- Authway Server, and what it does with the address -->
          <text x="292" y="62" text-anchor="middle" class="fill-slate-700 text-[12px] font-medium dark:fill-slate-200">
            {{ shown ? "keeps the peer's address" : "uses its own address" }}
          </text>
          <rect x="232" y="72" width="120" height="56" rx="10" class="fill-white stroke-sky-600 dark:fill-slate-900 dark:stroke-sky-400" stroke-width="1.5" />
          <text x="292" y="95" text-anchor="middle" class="fill-slate-800 text-[13px] font-semibold dark:fill-slate-100">Authway Server</text>
          <text x="292" y="114" text-anchor="middle" class="fill-slate-600 font-mono text-[12px] dark:fill-slate-300">{{ authway }}</text>

          <!-- the computer of the network -->
          <rect x="500" y="72" width="120" height="56" rx="10" class="fill-white stroke-slate-300 dark:fill-slate-900 dark:stroke-slate-600" />
          <text x="560" y="95" text-anchor="middle" class="fill-slate-800 text-[13px] font-semibold dark:fill-slate-100">Computer</text>
          <text x="560" y="114" text-anchor="middle" class="fill-slate-600 font-mono text-[12px] dark:fill-slate-300">{{ computer }}</text>

          <!-- the router of the network -->
          <rect x="314" y="178" width="224" height="50" rx="10" class="fill-white stroke-slate-300 dark:fill-slate-900 dark:stroke-slate-600" />
          <text x="426" y="198" text-anchor="middle" class="fill-slate-800 text-[13px] font-semibold dark:fill-slate-100">Router</text>
          <text v-if="shown" x="426" y="217" text-anchor="middle" class="fill-slate-700 font-mono text-[12px] dark:fill-slate-200">
            {{ tunnel }} via {{ authway }}
          </text>
          <text v-else x="426" y="217" text-anchor="middle" class="fill-slate-500 text-[12px] dark:fill-slate-400">
            no changes needed
          </text>
        </svg>
      </div>

      <ul class="flex flex-wrap gap-x-5 gap-y-1 text-xs text-slate-500 dark:text-slate-400" aria-hidden="true">
        <li class="flex items-center gap-2">
          <span class="h-0.5 w-5 rounded" style="background: var(--chart-1)" />What the peer sends
        </li>
        <li class="flex items-center gap-2">
          <span class="h-0.5 w-5 rounded" style="background: var(--chart-2)" />The answer
        </li>
        <li>{{ real ? "This server's addresses" : 'Example addresses' }}</li>
      </ul>

      <ul v-if="!shown" class="list-disc space-y-1.5 pl-5">
        <li>
          Authway Server replaces each peer's address with its own, so computers on the network see every peer as
          <span class="font-mono">{{ authway }}</span>. With the default compose.yaml setup, that's the Docker host's
          address.
        </li>
        <li>They reply to that address directly, so no router changes are needed.</li>
        <li>Their logs and firewall rules can't tell peers apart, and they can't open connections to peers.</li>
        <li>Works on any Docker host: a virtual machine, Wi-Fi or a cloud server.</li>
      </ul>
      <template v-else>
        <ul class="list-disc space-y-1.5 pl-5">
          <li>
            Authway Server keeps each peer's address, so computers see <span class="font-mono">{{ peer }}</span>, and
            their logs and firewall rules can tell peers apart.
          </li>
          <li>
            <span class="font-mono">{{ peer }}</span> isn't on the local network, so they send replies to their
            router. The router needs a route to the VPN network through Authway Server:
            <span class="font-mono">{{ tunnel }} via {{ authway }}</span>.
            <template v-if="!real">Each server's panel shows the exact route to add.</template>
          </li>
          <li>
            There are two ways to set this up, and the System page checks both:
            <ul class="mt-1 list-[circle] space-y-1 pl-5">
              <li>
                <span class="font-medium">Through the Docker host</span>, with compose.host-routes.yaml. The container
                stays on Docker's default network, and a helper adds a route on the Docker host that forwards VPN traffic
                to it.
                <template v-if="throughHost"><span class="font-mono">{{ authway }}</span> is the Docker host's address.</template>
                Works on virtual machines and over Wi-Fi.
                <template v-if="real && throughHost">This Authway Server is set up this way.</template>
              </li>
              <li>
                <span class="font-medium">Its own address</span>, with compose.macvlan.yaml. The container joins the
                local network directly<template v-if="ownAddress">, at <span class="font-mono">{{ authway }}</span></template>.
                The Docker host itself can't reach it, and a virtual machine needs promiscuous mode (see below).
                <template v-if="real && ownAddress">This Authway Server is set up this way.</template>
              </li>
            </ul>
          </li>
          <li>
            Only the server's networks are routed. Internet traffic from peers still goes out with Authway Server's
            address.
          </li>
          <li>
            With "Allow your networks to connect to peers" turned on, computers can also open connections to peers. On
            servers that require a login, only logged-in peers can be reached.
          </li>
        </ul>
        <UiNotice title="compose.macvlan.yaml on a virtual machine">
          <p>
            macvlan gives the container its own MAC address, so the hypervisor's virtual switch must allow it by enabling
            promiscuous mode. Until then, the network gets no replies from the container. None of this is needed when
            routing through the Docker host.
          </p>
          <ul class="mt-1.5 list-disc space-y-1 pl-5">
            <li>VMware Fusion: Settings, Network: uncheck "Require authentication to enter promiscuous mode"</li>
            <li>VMware ESXi: set Promiscuous mode and Forged transmits to Accept on the VM's port group</li>
            <li>Hyper-V: turn on Enable MAC address spoofing in the advanced features of the VM's network adapter</li>
            <li>VirtualBox: set Promiscuous Mode to Allow All on the bridged adapter</li>
            <li>Proxmox: works on its bridge; if the VM's firewall is on, turn off its MAC filter</li>
          </ul>
          <p class="mt-1.5">
            This doesn't work over Wi-Fi, so use a cable. Most cloud servers don't support it either, because their
            network only knows the VM's MAC address. Route through the Docker host instead.
          </p>
        </UiNotice>
      </template>
    </div>
    <template #footer>
      <UiButton @click="emit('close')">Close</UiButton>
    </template>
  </UiModal>
</template>
