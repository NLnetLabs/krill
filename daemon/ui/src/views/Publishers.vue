<template>
  <div>
    <h3 v-if="loading">
      <i class="el-icon-loading"></i>
      {{ $t("publishers.loading") }}
    </h3>

    <el-card class="box-card" v-if="!loading">
      <div slot="header" class="clearfix">
        <el-breadcrumb separator-class="el-icon-arrow-right">
          <el-breadcrumb-item :to="{ path: '/' }">{{ $t("publishers.publishers") }}</el-breadcrumb-item>
        </el-breadcrumb>
        <div class="search-input">
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
        <el-table
          v-if="filteredPublishers"
          :data="filteredPublishers"
          @row-click="loadPublisher"
          style="width: 100%"
        >
          <el-table-column label="Handle">
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

    <el-dialog :title="$t('publishers.add')" :visible.sync="dialogFormVisible">
      <el-form :model="form">
        <el-form-item label="Handle" :label-width="formLabelWidth">
          <el-input v-model="form.handle" autocomplete="off"></el-input>
        </el-form-item>
        <el-form-item label="URI" :label-width="formLabelWidth">
          <el-input v-model="form.uri" autocomplete="off"></el-input>
        </el-form-item>
        <el-form-item label="Token" :label-width="formLabelWidth">
          <el-input v-model="form.token" autocomplete="off"></el-input>
        </el-form-item>
      </el-form>
      <el-alert type="error" v-if="error" :closable="false">{{error}}</el-alert>
      <span slot="footer" class="dialog-footer">
        <el-button @click="dialogFormVisible = false">Cancel</el-button>
        <el-button
          type="primary"
          @click="addPublisher"
          :disabled="form.handle == '' || form.uri == '' || form.token == ''"
        >Confirm</el-button>
      </span>
    </el-dialog>
  </div>
</template>

<script>
import router from "@/router";
import APIService from "@/services/APIService.js";
export default {
  data() {
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
      formLabelWidth: "120px"
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
        .then(response => {
          this.dialogFormVisible = false;
          this.loadPublishers();
        })
        .catch(function(error) {
          self.error = error;
        });
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
</style>
