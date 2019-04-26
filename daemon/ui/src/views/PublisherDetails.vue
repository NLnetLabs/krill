<template>
  <div>
    <el-card class="box-card" v-if="publisher.handle">
      <div slot="header" class="clearfix">
        <el-breadcrumb separator-class="el-icon-arrow-right">
          <el-breadcrumb-item :to="{ path: '/' }">{{ $t("publishers.publishers") }}</el-breadcrumb-item>
          <el-breadcrumb-item>{{ handle }}</el-breadcrumb-item>
        </el-breadcrumb>
        <div class="retire" v-if="!loading && publisher && !publisher.deactivated">
          <el-form :inline="true">
            <el-form-item>
              <el-button
                class="retire"
                icon="el-icon-delete"
                type="primary"
                round
                size="mini"
                @click="confirmRetirePublisher"
              >{{ $t("publishers.retire") }}</el-button>
            </el-form-item>
          </el-form>
        </div>
      </div>
      <div class="text item">
        <span v-if="loading">
          <i class="el-icon-loading"></i>
          <span v-t="{ path: 'publisherDetails.loading', args: { handle: handle } }"></span>
        </span>
        <el-table v-if="!loading && publisher" :data="[publisher]" style="width: 100%">
          <el-table-column prop="base_uri" label="Base URI"></el-table-column>
          <el-table-column :label="$t('publisherDetails.notretired')" width="150" align="center">
            <template slot-scope="scope">
              <strong>
                <i class="el-icon-check" v-if="![publisher][scope.$index].deactivated"></i>
                <i class="el-icon-close" v-if="[publisher][scope.$index].deactivated"></i>
              </strong>
            </template>
          </el-table-column>
        </el-table>

        <div class="publisher-data">Publisher Data <i class="el-icon-loading" v-if="loadingPublisherData"></i></div>

        <el-table v-if="!loadingPublisherData && publisherData.elements" :data="publisherData.elements" style="width: 100%">
          <el-table-column prop="uri" label="URI"></el-table-column>
          <el-table-column prop="hash" label="Hash"></el-table-column>
        </el-table>

        <div
          v-if="!loadingPublisherData && publisherData.elements == null"
        >{{ $t("publisherDetails.nopublisherdata") }}</div>
      </div>
    </el-card>
  </div>
</template>

<script>
import router from "@/router";
import APIService from "@/services/APIService.js";
export default {
  data() {
    return {
      handle: this.$route.params.handle,
      loading: false,
      loadingPublisherData: false,
      publisher: {},
      publisherData: {}
    };
  },
  created() {
    this.loading = true;
    this.loadingPublisherData = true;
    APIService.getPublisher(this.handle).then(response => {
      this.loading = false;
      this.publisher = response.data;
    });
    APIService.getPublisherData(this.handle).then(response => {
      this.loadingPublisherData = false;
      this.publisherData = response.data;
    });
  },
  methods: {
    confirmRetirePublisher() {
      this.$confirm(
        this.$t("publisherDetails.confirm.message"),
        this.$t("publisherDetails.confirm.title"),
        {
          confirmButtonText: this.$t("publisherDetails.confirm.ok"),
          cancelButtonText: this.$t("publisherDetails.confirm.cancel")
        }
      )
        .then(() => {
          APIService.retirePublisher(this.handle).then(() => {
            this.$notify({
              title: this.handle + this.$t("publisherDetails.confirm.retired"),
              message: this.$t("publisherDetails.confirm.success"),
              type: "success"
            });
            router.push("/");
          });
        })
        .catch(() => {});
    },
    getFile(uri) {
      APIService.getEndpoint(uri).then(response => {
        console.log("got file", uri);
        console.log(response.data);
      });
    }
  }
};
</script>

<style lang="scss" scoped>
a {
  color: #F63107;
  &:hover {
    color: #f85a39;
  }
}
.box-card {
  margin: 2rem;
}
.retire {
  float: right;
  margin-top: -10px;
}

.publisher-data {
  font-size: 14px;
  margin-top: 3rem;
  margin-bottom: 1rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid #F9EADD;
}
</style>
