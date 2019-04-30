<template>
    <div>

        <router-link :to="{ name: 'publishers'}">
            <div class="text item">
                <span>Publishers</span>
            </div>
        </router-link>

        <router-link :to="{ name: 'trustanchor'}">
            <div class="text item">
                <span>Trust Anchor</span>
            </div>
        </router-link>

    </div>

</template>