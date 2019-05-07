<template>
    <div>
        <span v-show="hasTa">
            {{ $t("trustanchor.present") }}

            <el-table :data="[taData]" style="width: 100%">
                <el-table-column prop="resources.asn.Blocks" label="ASNs"></el-table-column>
                <el-table-column prop="resources.v4" label="IPv4"></el-table-column>
                <el-table-column prop="resources.v6" label="IPv6"></el-table-column>
            </el-table>

        </span>
        <span v-show="noTa">
            {{ $t("trustanchor.absent") }}
            <el-form :inline="true">
                <el-form-item>
                    <el-button
                        class="retire"
                        icon="el-icon-plus"
                        type="primary"
                        round
                        size="mini"
                        @click="dialogFormVisible = true"
                    >{{ $t("trustanchor.add") }}</el-button>
                </el-form-item>
            </el-form>
        </span>

        <el-dialog :title="$t('trustanchor.add')"
                   :visible.sync="dialogFormVisible"
                   :close-on-click-modal="false">

            {{ $t("trustanchor.sure") }}


            <div style="height: 20px"></div>

            <el-form :inline="true">

                <el-row type="flex" class="modal-footer" justify="end">
                    <el-form-item>
                        <el-button @click="hide_init_form()">{{ $t('form.cancel')
                        }}</el-button>
                        <el-button
                                type="primary"
                                @click="init_ta()"
                        >{{ $t('form.confirm') }}</el-button>
                    </el-form-item>
                </el-row>
            </el-form>

        </el-dialog>

    </div>

</template>

<script>
    // import router from "@/router";
    import APIService from "@/services/APIService.js";

    export default {

        data() {

            return {
                hasTa: false,
                noTa: false,
                dialogFormVisible: false,
                taData: {}
            };
        },
        created() {
            this.load_ta();
        },

        methods: {
            load_ta: function() {

                const self = this;

                APIService.getTrustAnchor().then(response => {
                    self.hasTa = true;
                    self.noTa = false;
                    self.taData = response.data;
                   response.toString()
                }).catch( () => {
                    self.hasTa = false;
                    self.noTa = true;
                });
            },

            hide_init_form: function () {
                this.dialogFormVisible = false;
            },

            init_ta: function () {
                APIService.initTrustAnchor();
                this.load_ta();
                this.dialogFormVisible = false;
            }
        }

    }

</script>