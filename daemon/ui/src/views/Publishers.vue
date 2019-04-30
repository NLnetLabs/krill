<template>
  <div>

    <el-card class="box-card">
      <div slot="header" class="clearfix">
        <el-breadcrumb separator-class="el-icon-arrow-right">
          <el-breadcrumb-item :to="{ path: '/' }">{{ $t("publishers.publishers") }}</el-breadcrumb-item>
        </el-breadcrumb>
        <div class="search-input" v-if="!loading">
          <el-form :inline="true">
            <el-form-item>
              <el-input
                size="mini"
                :placeholder="$t('publishers.search')"
                prefix-icon="el-icon-search"
                v-model="search"
                clearable
              ></el-input>
            </el-form-item>

            <el-form-item>
              <el-button
                class="retire"
                icon="el-icon-plus"
                type="primary"
                round
                size="mini"
                @click="dialogFormVisible = true"
              >{{ $t("publishers.add") }}</el-button>
            </el-form-item>
          </el-form>
        </div>
      </div>
      <div class="text item">
        <span v-if="loading">
          <i class="el-icon-loading"></i>
          {{ $t("publishers.loading") }}
        </span>
        <el-table
          v-if="filteredPublishers"
          :data="filteredPublishers"
          @row-click="loadPublisher"
          style="width: 100%"
        >
          <el-table-column label="Handle" v-if="!loading">
            <template slot-scope="scope">
              <router-link
                :to="{ name: 'publisherDetails', params: { handle: filteredPublishers[scope.$index].id }}"
              >
                <el-button type="text">{{ filteredPublishers[scope.$index].id }}</el-button>
              </router-link>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </el-card>

    <el-dialog :title="$t('publishers.add')" :visible.sync="dialogFormVisible" :close-on-click-modal="false">
      <el-form :model="form" :rules="rules" ref="addPublisherForm">
        <el-form-item label="Handle" prop="handle">
          <el-input v-model="form.handle" autocomplete="off"></el-input>
        </el-form-item>
        <el-form-item label="URI" placeholder="rsync://HOST/folder/" prop="uri">
          <el-input v-model="form.uri" autocomplete="off"></el-input>
        </el-form-item>
        <el-form-item label="Token" prop="token">
          <el-input v-model="form.token" autocomplete="off"></el-input>
        </el-form-item>
        <el-alert type="error" v-if="error" :closable="false">{{error}}</el-alert>
        <el-row type="flex" class="modal-footer" justify="end">
          <el-form-item>
            <el-button @click="resetForm('addPublisherForm')">{{ $t('form.cancel') }}</el-button>
            <el-button
              type="primary"
              @click="submitForm('addPublisherForm')"
            >{{ $t('form.confirm') }}</el-button>
          </el-form-item>
        </el-row>
      </el-form>
    </el-dialog>
  </div>
</template>

<script>
import router from "@/router";
import APIService from "@/services/APIService.js";
export default {
  data() {

    var check_rsync_uri = (rule, value, callback) => {
      if (value === "") {
        callback(new Error(this.$t("form.required")));
      } else {
        if (new RegExp(/rsync:\/\/[^\s]+\/[^\s]+\//gm).test(value)) {
          callback();
        } else {
          callback(new Error(this.$t("form.rsync_uri_format")));
        }
      }
    };

    return {
      loading: false,
      publishers: [],
      search: "",
      dialogFormVisible: false,
      error: "",
      form: {
        handle: "",
        token: "",
        uri: ""
      },
      rules: {
        handle: [{ required: true, message: this.$t("form.required") }],
        uri: [{ validator: check_rsync_uri, required: true }],
        token: [{ required: true, message: this.$t("form.required") }]
      }
    };
  },
  computed: {
    filteredPublishers: function() {
      let src = this.search;
      return this.publishers.filter(function(publisher) {
        return publisher.id.toLowerCase().indexOf(src) > -1;
      });
    }
  },
  created() {
    this.loading = true;
    this.loadPublishers();
  },
  methods: {
    sortPublishers: function(publishers) {
      return [...publishers].sort(function(a, b) {
        const handleA = a.id.toLowerCase();
        const handleB = b.id.toLowerCase();

        if (handleA > handleB) {
          return 1;
        } else if (handleA < handleB) {
          return -1;
        }
        return 0;
      });
    },
    loadPublishers: function() {
      APIService.getPublishers().then(response => {
        this.loading = false;
        this.publishers = response.data.publishers;
      });
    },
    loadPublisher: function(row) {
      router.push("/publishers/" + row.id);
    },
    addPublisher: function() {
      const self = this;
      APIService.addPublisher(this.form.handle, this.form.uri, this.form.token)
        .then(() => {
          this.dialogFormVisible = false;
          this.loadPublishers();
        })
        .catch(function(error) {
          let e = self.$t('errors.' + error.data.code);
          if (e === 'errors.' + error.data.code) {
            e = error.data.msg;
          }
          self.error = e;
        });
    },
    submitForm(formName) {
      this.$refs[formName].validate(valid => {
        if (valid) {
          this.addPublisher();
        } else {
          return false;
        }
      });
    },
    resetForm(formName) {
      this.error = '';
      this.dialogFormVisible = false;
      this.$refs[formName].resetFields();
    }
  }
};
</script>

<style lang="scss" scoped>
.box-card {
  margin: 2rem;
}
.search-input {
  float: right;
  margin-top: -27px;
}
.modal-footer {
  margin-top: 30px;
  .el-form-item {
    margin-bottom: 0;
  }
}
</style>
