import Vue from 'vue'
import Router from 'vue-router'
import Login from './views/Login.vue'
import Publishers from './views/Publishers.vue'
import PublisherDetails from './views/PublisherDetails.vue'

Vue.use(Router)

const router = new Router({
  routes: [
    {
      path: '/',
      name: 'publishers',
      component: Publishers
    },
    {
      path: '/login',
      name: 'login',
      component: Login
    },
    {
      path: '/publishers/:handle',
      name: 'publisherDetails',
      component: PublisherDetails
    },
  ]
});

router.beforeEach((to, from, next) => {
  // redirect to login page if not logged in and trying to access a restricted page
  const publicPages = ['/login'];
  const authRequired = !publicPages.includes(to.path);
  const loggedIn = localStorage.getItem('user');

  if (authRequired && !loggedIn) {
    return next({ 
      path: '/login', 
      query: { returnUrl: to.path } 
    });
  }

  next();
});

export default router;
