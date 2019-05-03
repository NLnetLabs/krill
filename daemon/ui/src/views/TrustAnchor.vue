<template>
    <div>
        <span v-if="hasTa">
            {{ $t("trustanchor.present") }}
        </span>
        <span v-else>
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

            <el-form :model="form" :inline="true">

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
                dialogFormVisible: false,
                taDetails: ""
            };
        },
        created() {
            this.load_ta();
        },

        methods: {
            load_ta: function() {
                const self = this;

                APIService.getTrustAnchor().then(response => {
                   if (response.statusCode == 200) {
                       self.hasTa = true;
                   }
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