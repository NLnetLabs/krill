<template>
  <div>
    <h3 v-if="loading">
      <i class="el-icon-loading"></i>
      <span v-t="{ path: 'publisherDetails.loading', args: { handle: handle } }"></span>
    </h3>

    <el-card class="box-card" v-if="!loading && publisher.handle">
      <div slot="header" class="clearfix">
        <el-breadcrumb separator-class="el-icon-arrow-right">
          <el-breadcrumb-item :to="{ path: '/' }">{{ $t("publishers.publishers") }}</el-breadcrumb-item>
          <el-breadcrumb-item>{{ handle }}</el-breadcrumb-item>
        </el-breadcrumb>
        <el-button
          class="retire"
          icon="el-icon-delete"
          type="primary"
          circle
          @click="confirmRetirePublisher"
        ></el-button>
      </div>
      <div class="text item">
        Base URI:
        <a :href="publisher.base_uri" target="_blank">{{ publisher.base_uri }}</a>
        <br>
        RFC 8181: {{ publisher.rfc8181 }}
        <br>
        Retired: {{ publisher.retired }}
        <br>Links:
        <ul>
          <li v-for="link in publisher.links" :key="link.link">
            <a href="#" @click="getFile(link.link)">{{ link.rel }}</a>
          </li>
        </ul>
        <br>Publisher Data:
        <i class="el-icon-loading" v-if="loading"></i>
        <ul v-if="!loadingPublisherData && publisherData.elements">
          <li v-for="element in publisherData.elements" :key="element.hash">
            <a :href="element.uri" target="_blank">{{ element.uri }}</a>
            - {{ element.hash }}
          </li>
        </ul>
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
  color: #de4e00;
}
.box-card {
  margin: 2rem;
}
.retire {
  float: right;
}
</style>
