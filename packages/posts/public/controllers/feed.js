/**
 * Created by Leonid on 03/08/14.
 */
'use strict';
angular.module('mean.posts').controller('FeedController', [
    '$resource', '$modal', '$scope', '$rootScope', '$stateParams',
    '$location', 'Global', 'Posts', 'SearchPosts', 'MapUtils',
    function ($resource, $modal, $scope, $rootScope, $stateParams, $location, Global, Posts, SearchPosts, MapUtils) {
        $scope.global = Global;

        $scope.profilePictureUrl = null;
        $scope.newPost = null;

        var unbind = $rootScope.$on('fbLogin', function (event) {
            console.log('feed fblogin');

            $scope.queryPosts();
        });
        $scope.$on('$destroy', unbind);

        $scope.initFeed = function() {
            if ($scope.posts === undefined) {
                $scope.queryPosts();
            }
        };

        $scope.loadInstagramPosts = function() {
            var instagramTest = $resource('https://api.instagram.com/v1/tags/coffee/media/recent',
                {
                    access_token:'@access_token',
                    callback: 'JSON_CALLBACK'
                }, {
                    getPosts : {
                        method: 'JSONP'
                    }
                }
            );


            instagramTest.getPosts({ access_token : window.user.instagramAccessToken}).$promise.then(function(data) {
                console.log('data', data);
            }, function(errResponse) {
                // fail
                console.log('errResponse', errResponse);
            });


        };
        $scope.createNewPostForEdit = function() {
            $scope.newPost = new Posts({
                title: 'title',
                content: 'I am here now!',
                created : Date.now,
                saving : false,
                location: {
                    type: 'Point',
                    coordinates: [$scope.map.clickedMarker.longitude, $scope.map.clickedMarker.latitude]
                }
            });

            var locationString = 'location='+ $scope.newPost.location.coordinates[1]+','+$scope.newPost.location.coordinates[0];
            $scope.newPost.streetViewUrl = 'http://maps.googleapis.com/maps/api/streetview?sensor=false&size=900x380&heading=34&pitch=10&'+locationString;

            $scope.newPost.formattedCreated = moment().fromNow(); // 3 years ago

        };


        $scope.create = function () {
            console.log('create..', $scope.newPost);


            var post = new Posts({
                title: 'title',
                content: $scope.newPost.content,
                created : Date.now,
                location: {
                    type: 'Point',
                    coordinates: [$scope.map.clickedMarker.longitude, $scope.map.clickedMarker.latitude]
                }
            });

            var pNewPost = $scope.newPost;
            pNewPost.saving = true;
            console.log('save post:', post);

            post.$save(function (response) {
                console.log(response);
                //$location.path('posts/' + response._id);
                pNewPost.saving = false;
                $scope.posts.unshift(response);
                $scope.newPost = null;
            });

        };

        $scope.queryPosts = function() {
            if ($scope.posts !== undefined) {
                if ($scope.posts.length === 0) {
                    console.log('loading');
                    return;
                }

            }




            if ($scope.global.fb.loginStatus !== undefined && $scope.map.bounds.northeast !== undefined) {
                $scope.posts = [];
                console.log('$scope.global.fb.loginStatus', $scope.global.fb.loginStatus, ' b:', $scope.map.bounds);
                $scope.searchByRectangle();
            } else {
                console.log('cant query, $scope.global.fb.loginStatus', $scope.global.fb.loginStatus, ' b.northeast:', $scope.map.bounds.northeast);
            }
        };

        $scope.searchByRectangle = function () {


            var params = {
                bounds: $scope.map.bounds,
                tags: ['food', 'fun']
            };

            SearchPosts.searchWithFilter(params, function (posts) {
                console.log('callback posts:', posts);

                $scope.posts = posts;
                $scope.map.postsMarkers = [];

                for (var i = 0; i < posts.length; i++) {
                    var marker = { showWindow: true, id: i};
                    var post = posts[i];
                    marker.title = post.title;
                    marker.longitude = post.location.coordinates[0];
                    marker.latitude = post.location.coordinates[1];
                    //console.log(marker);
                    $scope.map.postsMarkers.push(marker);

                   // '2014-08-02T23:37:12.988Z'
                    post.formattedCreated = moment(post.created, 'YYYY-MM-DDThh:mm:ss.ms').fromNow(); // 3 years ago
                    var locationString = 'location='+ post.location.coordinates[1]+','+post.location.coordinates[0];
                    post.streetViewUrl = 'http://maps.googleapis.com/maps/api/streetview?sensor=false&size=900x380&heading=34&pitch=10&'+locationString;
                    //console.log( post.formattedCreated);
                }
               // $scope.$apply();
            });
        };


        $scope.map = {
            countNotFiltered : 0,
            categories: {},
            categoriesSorted: [],
            postsMarkers: [],
            controls: {},

            events: {
                idle: function (map, eventName, originalEventArgs) {

                    console.log('idl');

                    console.log('idle bounds:', $scope.map.bounds);

                    var mapNative = $scope.map.controls.getGMap();

                    var newbounds = MapUtils.getBoundsFromNative(mapNative);
                    //console.log('idle newbounds:', newbounds);

                    if ($scope.map.bounds.northeast === undefined) {
                        $scope.map.bounds.northeast = newbounds.northeast;
                        $scope.map.bounds.southwest = newbounds.southwest;
                    }
                    $scope.posts = undefined;
                    $scope.queryPosts();
                },
                tilesloaded: function (map, eventName, originalEventArgs) {
                    //console.log('tilesloaded');
                    //$scope.queryPosts();
                },
                zoom_changed: function (map, eventName, originalEventArgs) {
                    //console.log('zoom_changed');
                    //$scope.queryPosts();
                },
                bounds_changed: function (map, eventName, originalEventArgs) {
                    //console.log('bounds_changed');
                    //$scope.queryPosts();
                },
                dragend: function (map, eventName, originalEventArgs) {
                    //console.log('dragend');
                    //$scope.queryPosts();
                },
                click: function (mapModel, eventName, originalEventArgs) {
                    // 'this' is the directive's scope
                    console.log('user defined event: ' + eventName, mapModel, originalEventArgs);

                    var e = originalEventArgs[0];
                    $scope.map.clickedMarker = {
                            title: 'Your virtual location',
                            latitude: e.latLng.lat(),
                            longitude: e.latLng.lng()
                        };

                    console.log('marker: ', $scope.map.clickedMarker);
                    $scope.createNewPostForEdit();
                    $scope.$apply();
                }
            },
            center: {
                latitude: 32.07771034554237,
                longitude: 34.76860736083985 },
            zoom: 19, bounds: {}
        };
    }]);