'use strict';

var PostModalController = function ($scope, $modalInstance, items) {
    $scope.items = items;
    $scope.selected = {
        item: $scope.items[0]
    };

    $scope.ok = function () {
        $modalInstance.close($scope.selected.item);
    };

    $scope.cancel = function () {
        $modalInstance.dismiss('cancel');
    };
};


angular.module('mean.posts').controller('PostsController', ['$modal', '$scope', '$rootScope', '$stateParams', '$location', 'Global', 'Posts',
    function ($modal, $scope, $rootScope, $stateParams, $location, Global, Posts) {
        $scope.global = Global;

        $scope.package = {
            name: 'posts'
        };

        var unbind = $rootScope.$on('golocation', function (event, loc) {
            console.log('event go location:', loc);
            $scope.map.clickedMarker = {
                title: 'found',
                latitude: loc.latitude,
                longitude: loc.longitude
            };

            $scope.gotoLocation(loc.latitude, loc.longitude);
            $scope.addressFromLocation($scope.map.clickedMarker);
        });
        $scope.$on('$destroy', unbind);

        $scope.addressFromLocation = function (marker) {
            var lat = marker.latitude;
            var lng = marker.longitude;

            if (!this.geocoder) this.geocoder = new google.maps.Geocoder();
            var latlng = new google.maps.LatLng(lat, lng);
            this.geocoder.geocode({'latLng': latlng}, function (results, status) {
                if (status === google.maps.GeocoderStatus.OK) {
                    //console.log(results);
                    marker.address = results;
                } else {
                    marker.address = [
                        {address_components: [
                            {short_name: 'unknown'}
                        ]}
                    ];
                }
                marker.title = 'selected';
                $scope.$apply();
            });
        };

        $scope.gotoLocation = function (lat, lon) {
            $scope.map.center.latitude = lat;
            $scope.map.center.longitude = lon;
            $scope.map.zoom = 14;
            $scope.$apply();
        };

        $scope.initPosts = function () {
            //$scope.queryPosts();

            if ($scope.global.authenticated) {
                console.log('posts, query FB login status');

                $scope.loginStatus = FB.getLoginStatus(function (response) {
                    if (response.status === 'connected') {
                        console.log('posts, Logged in.', response);
                        //$scope.queryPosts();
                    }
                    else {
                        console.log('call login again??');
                        FB.login(function () {
                            console.log('FB login callback', $scope);
                            //$scope.queryPosts();
                        });
                    }
                });


            } else {
                console.log('not authenticated');
            }
        };

        $scope.queryStreetPosts = function () {

        };

        $scope.getPlaceFeed = function (place) {
            FB.api('/' + place.id + '/feed', function (response) {
                console.log(place.name, 'res--------:', response);
                place.feedResponse = response;
                place.postsWithImages = [];
                if (response.data !== null) {
                    for (var i1 = 0; i1 < response.data.length; i1++) {
                        var post = response.data[i1];
                        if (post.message !== undefined) {
                            if (post.message.indexOf('?') !== -1) {
                                post.hint = 'question';
                            } else if (post.message.indexOf('!') !== -1) {
                                post.hint = 'exclamation';
                            } else if (post.message.length < 13) {
                                post.hint = 'remarks';
                            } else {
                                post.hint = 'story';
                            }
                        }
                    }

                    // find some pictures
                    var count = 0;
                    for (var i = 0; i < 40 && i < response.data.length; i++) {
                        var post1 = response.data[i];
                        if (post1 === undefined) {
                            //console.log('undefined for '+i);
                            continue;
                        }
                        //console.log('p:' + post1.picture);
                        if (post1.picture !== undefined && post1.picture !== '') {

                            place.postsWithImages.push(post1);
                            count++;
                            if (count === 6) {
                                break;
                            }
                        }
                    }
                }
                $scope.$apply();
            });

        };

        $scope.addCategory = function (cMap, category) {
            var key = category.toLowerCase();
            if (cMap[key] === undefined) {
                cMap[key] = { count: 0, name: category, selected: false, top: false};
                $scope.map.categoriesSorted.push(cMap[key]);
            }
            cMap[key].count++;

            return cMap[key];
        };

        $scope.filterCategories = function() {
            // mark filtered
            for (var i = 0; i < $scope.map.placesMarkers.length; i++) {
                var marker = $scope.map.placesMarkers[i];
                var place = marker.place;
                place.filtered = true;
                var category = place.category.toLowerCase();


                if ($scope.map.categories[category] !== undefined) {
                    //console.log('$scope.map.categories[category]', $scope.map.categories[category]);
                    if ($scope.map.categories[category].selected) {
                        console.log('category', category);
                        place.filtered = false;
                        //continue;
                    }

                } else {
                    console.log('no category:', category);
                }

                for (var j = 0; place.category_list !== undefined && j < place.category_list.length; j++) {
                    var catInList = '' + place.category_list[j].name.toLowerCase(); // stringify it
                    if ($scope.map.categories[catInList] !== undefined) {
                        if ($scope.map.categories[catInList].selected) {
                            //console.log('catInList', catInList);
                            place.filtered = false;

                        }
                    }
                }
            }

            $scope.map.countNotFiltered = 0;
            for (var i1 = 0; i1 < $scope.map.placesMarkers.length; i1++) {
                var marker1 = $scope.map.placesMarkers[i1];
                var place1 = marker1.place;
                //console.log('place.filtered', place.filtered);
                if (place1.filtered === false) {
                    $scope.map.countNotFiltered++;
                }

            }
        };

        $scope.sortPlacesByDistance = function(from) {
            var googleFrom = new google.maps.LatLng(from.latitude, from.longitude);

            for (var i = 0; i < $scope.fbPlaces.data.length; i++) {
                var place = $scope.fbPlaces.data[i];

                var m = new google.maps.LatLng(place.location.latitude, place.location.longitude);
                var dist = google.maps.geometry.spherical.computeDistanceBetween(googleFrom, m);
                place.distance = Math.round(dist);
            }



            $scope.fbPlaces.data.sort(function(a, b) {
                if (a.distance > b.distance)  return 1;
                if (a.distance < b.distance)  return -1;
                return 0;
            });
        };
        $scope.toggleCategory = function (categoryObject) {
            categoryObject.selected = !categoryObject.selected;

            //console.log('categoryObject', categoryObject);
            $scope.filterCategories();
            $scope.recreatePlacesPage();
        };

        $scope.queryPlaces = function () {
            var center = 'center=' + $scope.map.center.latitude + ',' + $scope.map.center.longitude;
            FB.api(
                '/search?type=place&' + center + '&distance=100', function (response) {
                    console.log(response);
                    $scope.fbPlaces = response;

                    $scope.map.placesMarkers = [];
                    $scope.map.categories = {};
                    $scope.map.categoriesSorted = [];
                    if ($scope.fbPlaces !== undefined) {

                        $scope.sortPlacesByDistance($scope.map.center);

                        for (var i = 0; i < $scope.fbPlaces.data.length; i++) {
                            var marker = { showWindow: true, id: i};
                            var place = $scope.fbPlaces.data[i];
                            place.filtered = true;

                            marker.title = place.name;
                            marker.place = place;
                            marker.longitude = place.location.longitude;
                            marker.latitude = place.location.latitude;
                            //console.log(marker);
                            $scope.map.placesMarkers.push(marker);

                            // take care about categories
                            var category = place.category;
                            var topCategory = $scope.addCategory($scope.map.categories, category);
                            topCategory.top = true;
                            topCategory.selected = true;
                            for (var j = 0; place.category_list !== undefined && j < place.category_list.length; j++) {
                                var catInList = '' + place.category_list[j].name; // stringify it
                                //console.log('o:'+j, catInList);
                                if (category.toLowerCase() !== catInList.toLowerCase()) {
                                    $scope.addCategory($scope.map.categories, catInList);
                                } else {
                                    console.log('duplication-----------------');
                                }
                            }


                        }

                        $scope.filterCategories();

                        $scope.map.categoriesSorted.sort(function (a, b) {
                            if (a.count > b.count) return -1;
                            if (a.count < b.count) return 1;
                            return 0;
                        });



                        //console.log('cat', $scope.map.categories);
                        $scope.recreatePlacesPage();
                    }

                    $scope.$apply();
                });
        };

        $scope.recreatePlacesPage = function() {
            $scope.fbPlacesPage = [];
            var pageSize = 6;
            var count = 0;
            for (var i1 = 0; i1 < $scope.fbPlaces.data.length && count < pageSize; i1++) {
                var place1 = $scope.fbPlaces.data[i1];
                if (place1.filtered) {
                    continue;
                }
                $scope.getPlaceFeed(place1);
                $scope.fbPlacesPage.push(place1);
                count++;
            }
        };


        $scope.map = {
            countNotFiltered : 0,
            categories: {},
            categoriesSorted: [],
            placesMarkers: [],

            events: {
                tilesloaded: function (map, eventName, originalEventArgs) {
                    console.log('tilesloaded, bounds:', $scope.map.bounds);
                },
                zoom_changed: function (map, eventName, originalEventArgs) {
                    //console.log('zoom');
                },
                bounds_changed: function (map, eventName, originalEventArgs) {
                    //console.log('bounds', $scope.map.bounds);
                },
                dragend: function (map, eventName, originalEventArgs) {
                    //console.log('dragend', $scope.map.center);

                    //$scope.searchByRectangle();
                },
                click: function (mapModel, eventName, originalEventArgs) {
                    // 'this' is the directive's scope
                    console.log('user defined event: ' + eventName, mapModel, originalEventArgs);

                    var e = originalEventArgs[0];

                    if (!$scope.map.clickedMarker) {
                        $scope.map.clickedMarker = {
                            title: 'You clicked here',
                            latitude: e.latLng.lat(),
                            longitude: e.latLng.lng()
                        };
                    }
                    else {
                        var marker = {
                            latitude: e.latLng.lat(),
                            longitude: e.latLng.lng()
                        };
                        $scope.map.clickedMarker = marker;
                    }
                    $scope.map.clickedMarker.title = 'new post';
                    console.log('marker: ', $scope.map.clickedMarker);
                    $scope.$apply();
                }
            },
            center: {
                latitude: 32.07771034554237,
                longitude: 34.76860736083985 },
            zoom: 19, bounds: {}
        };

        $scope.openNewPostModal = function (size) {

            var modalInstance = $modal.open({
                templateUrl: 'newPostModalContent.html',
                controller: PostModalController,
                size: size,
                resolve: {
                    items: function () {
                        return ['1', '2'];
                    }
                }
            });

            modalInstance.result.then(function (selectedItem) {
                $scope.selected = selectedItem;
            }, function () {
                console.log('Modal dismissed at: ' + new Date());
            });
        };
    }
]);
