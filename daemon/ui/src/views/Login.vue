<template>
  <div class="login">
    <el-row type="flex" justify="center">
      <el-col :span="10">
        <el-card class="box-card">
          <div class="text item">
            <el-form :inline="true">
              <el-form-item :label="$t('login.password')">
                <el-input type="password" :placeholder="$t('login.placeholder')" v-model="token" clearable></el-input>
              </el-form-item>
              <el-form-item>
                <el-button type="primary" @click="login">{{ $t("login.signin") }}</el-button>
              </el-form-item>
            </el-form>
          </div>
        </el-card>
      </el-col>
    </el-row>
    <el-row type="flex" class="alert-row" justify="center">
      <el-col :span="10">
        <el-alert type="error" v-if="error">{{error}}</el-alert>
      </el-col>
    </el-row>
  </div>
</template>

<script>
import router from "../router";
import APIService from "@/services/APIService.js";

export default {
  data() {
    return {
      token: "",
      submitted: false,
      loading: false,
      returnUrl: "",
      error: ""
    };
  },
  created() {
    this.returnUrl = this.$route.query.returnUrl || "/";
  },
  methods: {
    login() {
      this.submitted = true;
      const token = this;
      if (!token) {
        return;
      }

      const self = this;

      this.loading = true;
      APIService.login(this.token)
        .then(() => {
          this.$emit("authEvent");
          router.push(this.returnUrl);
        })
        .catch(function(error) {
          self.error = error;
          self.loading = false;
        });
    }
  }
};
</script>

<style lang="scss" scoped>
.box-card {
  .el-form {
    padding: 2rem;
    text-align: center;
    .el-form-item {
      margin-bottom: 0 !important;
    }
  }
}
.alert-row {
  margin-top: 1rem;
}
</style>
