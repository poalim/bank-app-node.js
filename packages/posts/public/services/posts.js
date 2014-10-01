'use strict';


angular.module('mean.posts').factory('Posts', ['$resource',
    function($resource) {
        return $resource('posts/:postId', {
            articleId: '@_id'
        }, {
            update: {
                method: 'PUT'
            }
        });
    }
]);

angular.module('mean.posts').factory('SearchPosts', ['$resource',
    function($resource) {
        return $resource('searchposts', {

        }, {
            searchWithFilter : {
                method : 'POST',
                isArray:true
            }
        });
    }
]);
