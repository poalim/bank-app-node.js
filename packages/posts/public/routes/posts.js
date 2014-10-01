'use strict';

angular.module('mean.posts').config(['$stateProvider',
    function($stateProvider) {
        $stateProvider.state('Happening', {
            url: '/posts/happend',
            templateUrl: 'posts/views/index.html'
        });
        $stateProvider.state('Feed', {
            url: '/posts/feed',
            templateUrl: 'posts/views/feed.html'
        });
    }
]);
