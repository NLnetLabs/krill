<template>
  <div id="app">
    <el-container>
      <el-header>
        <el-row>
          <el-col :span="4">
            <router-link :to="{ name: 'home'}">
              <div class="logo">
                <img src="@/assets/images/krill_logo_white.svg">
              </div>
            </router-link>
          </el-col>
          <el-col :span="14">
            <el-menu
            v-if="user"
            :router="true"
            :default-active="activeIndex"
            mode="horizontal"
            background-color="#f63107"
            text-color="#fff"
            active-text-color="#fff">
              <el-menu-item index="1" :route="{ name: 'publishers'}">
                {{ $t("publishers.publishers") }}
              </el-menu-item>
              <el-menu-item index="2" :route="{ name: 'trustanchor'}">
                {{ $t("trustanchor.ta") }}
              </el-menu-item>
            </el-menu>
            &nbsp;
          </el-col>
          <el-col :span="6">
            <div class="toolbar">
              <el-select v-model="$i18n.locale" placeholder="Language" size="small">
                <el-option v-for="lang in langs" :key="lang.iso" :value="lang.iso" :label="lang.label"></el-option>
              </el-select>
              <font-awesome-icon icon="sign-out-alt" v-if="user" class="logout" @click="logout"/>
            </div>
          </el-col>
        </el-row>
      </el-header>

      <el-main>
        <router-view v-on:authEvent="loadUser"/>
      </el-main>
    </el-container>
  </div>
</template>



<style>
html,
body {
  padding: 0;
  margin: 0;
  font-family: "Lato", sans-serif;
  background-color: #fff;
}
.el-header {
  background: linear-gradient(45deg, #f63107, #f63107);
  line-height: 60px;
  color: #ffffff;
  z-index: 3;
}
.el-menu-item a {
  text-decoration: none;
}
.logo {
  line-height: 10px;
}
.logo img {
  width: 146px;
  margin-left: -14px;
}
.logout {
  margin-left: 2rem;
  cursor: pointer;
}

.toolbar {
  text-align: right;
}
</style>

<script>
import router from "@/router";
import APIService from "@/services/APIService.js";

export default {
  data() {
    return {
      user: null,
      langs: [
        {iso: "it", label: "Italiano"},
        {iso: "en", label: "English"}
      ],
      activeIndex: null
    };
  },
  watch: {
    $route (to, from) {
      this.activeIndex = this.getActiveIndex(to.name);
    }
  },
  mounted: function(){
    this.activeIndex = this.getActiveIndex(this.$route.name);
  },
  created() {
    this.loadUser();
  },
  methods: {
    getActiveIndex(path) {
      return ''+ (['publishers', 'trustanchor'].indexOf(path) + 1);
    },
    loadUser() {
      this.user = JSON.parse(localStorage.getItem("user"));
    },
    logout() {
      return APIService.logout().then(() => {
        this.user = null;
        router.push("/login");
      });
    }
  }
};
</script>