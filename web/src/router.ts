import { createRouter, createWebHistory } from 'vue-router'

import { setSetupRequiredHandler, setUnauthorizedHandler } from './api'
import { checkSession, isAdmin, session } from './state'
import AppLayout from './views/AppLayout.vue'
import LoginView from './views/LoginView.vue'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', name: 'login', component: LoginView, meta: { public: true } },
    // a new password or an authenticator, before the rest
    { path: '/setup', name: 'setup', component: () => import('./views/SetupView.vue') },
    {
      path: '/',
      component: AppLayout,
      children: [
        { path: '', redirect: '/servers' },
        { path: 'servers/:id?', name: 'servers', component: () => import('./views/ServersView.vue') },
        { path: 'users', name: 'users', component: () => import('./views/UsersView.vue') },
        { path: 'activity', name: 'activity', component: () => import('./views/ActivityView.vue') },
        // the resources of the host, the checks, the log: for when something goes wrong
        { path: 'system', name: 'system', component: () => import('./views/SystemView.vue') },
        { path: 'admins', name: 'admins', component: () => import('./views/AdminsView.vue'), meta: { admin: true } },
        { path: 'settings', name: 'settings', component: () => import('./views/SettingsView.vue') },
        // the own login: the authenticator app and the password
        { path: 'account', name: 'account', component: () => import('./views/AccountView.vue') },
      ],
    },
    { path: '/:rest(.*)*', redirect: '/servers' },
  ],
})

router.beforeEach(async (to) => {
  const loggedIn = await checkSession()
  if (!to.meta.public && !loggedIn) {
    return { name: 'login', query: to.fullPath !== '/servers' ? { next: to.fullPath } : {} }
  }
  if (!loggedIn) {
    return
  }
  const setup = session.me?.setup ?? ''
  if (setup && to.name !== 'setup') {
    return { name: 'setup' }
  }
  if (!setup && (to.name === 'setup' || to.name === 'login')) {
    return { path: '/servers' }
  }
  if (to.meta.admin && !isAdmin()) {
    return { path: '/servers' }
  }
})

setUnauthorizedHandler(() => {
  session.me = null
  if (router.currentRoute.value.name !== 'login') {
    router.push({ name: 'login' })
  }
})

setSetupRequiredHandler((step) => {
  if (session.me) {
    session.me.setup = step
  }
  if (router.currentRoute.value.name !== 'setup') {
    router.push({ name: 'setup' })
  }
})
