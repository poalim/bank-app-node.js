console.log('test');
var mongoose = require('mongoose');
var async = require('async');
var UserSchema = require('./../server/models/user.js');
var PostSchema = require('./../packages/posts/server/models/post.js');
var UserRootSchema = require('./../server/models/userroot.js');
//var assert = require('assert')

var User = mongoose.model('User');
var Post = mongoose.model('Post');
var UserRoot = mongoose.model('UserRoot');

console.log('\n===========');
console.log('    mongoose version: %s', mongoose.version, Post);
console.log('========\n\n');

//createMany();
var dbname = 'mean-dev';
mongoose.connect('localhost', dbname);
mongoose.connection.on('error', function () {
    console.error('connection error', arguments);
});


var example =
{ title: 'title',
    content: 'wow',
    location: { type: 'Point',
        coordinates: [ 34.777575731277466, 32.065992228606866 ] } };

var user0 = null;
mongoose.connection.on('open', function () {
    console.log('remove all');
    Post.remove().exec(function(err){
        console.log('removed all, err:', err);

        // get user to work with
        User.find().exec(function (err, users) {
            console.log(err, users);

            user0 = users[0];
            createMany(function() {
                console.log('createMany done');


                done();
            });
        });
    });

    //count();
    if (false) {
        UserRoot.find().exec(function (err, result) {
            console.log(err, result);
            done();
            return;
        });
        return;

        User.find().exec(function (err, users) {
            console.log(err, users);

            user0 = users[0];

//            var userroot = new UserRoot({user: user0});
//
//            userroot.save(function (err) {
//                console.log('userroot::', err);
//
//                done();
//            });
        });
    }
    //createMany();
    //count();


    //done();
});

function createUserRoot() {
    var userroot = new UserRoot({});
    userroot.save();
}

function count() {
    Post.find().exec(function (err, posts) {
        if (err) {
            console.log('err:', err);
        } else {
            console.log('l:', posts.length);
        }

        done();
    });
}


function createMany(callbackWhenDone) {
    var long = 0;
    var lat = 0;

    var calls = [];

    var count = 0;
    var cb = function (err, result) {
        console.log('in cb, ', err, result);
        if (err) {
            return err;
        }

        count++;

        console.log('count', count);
        if (count == calls.length) {
            callbackWhenDone();
        }
    };


    for (var i = -10; i < 10; i++) {
        for (var j = -10; j < 10; j++) {

            var myFunction = function (callback, i, j) {
                //console.log(i, ':', j);
                var long1 = long + i;
                var lat1 = lat + j;
                var pp = {
                    content: 'post with content_' + i + '_' + j,
                    location: {
                        type: 'Point',
                        coordinates: [long1, lat1]
                    }
                };

                console.log('creating');

                var post = new Post(pp);
                post.user = user0;
                post.save(function (err) {
                    console.log('creating?');
                    if (err) {
                        console.log('err:', err);
                        callback(err);
                        return;
                    }
                    console.log('created');
                    callback(null, 'created: ' + i + ':' + j);
                });

            };


            var myFunctionBinded = myFunction.bind(null, cb, i, j);

            calls.push(myFunctionBinded);


        }
    }

    for (var i = 0; i < calls.length; i++) {
        calls[i]();
    }
//    myFunction(function() {}, 1 ,2);
    //async.series(calls);


    console.log('here');


}
function done(err) {
    if (err) console.error(err.stack);
//    mongoose.connection.db.dropDatabase(function () {
//        mongoose.connection.close();
//    });

    mongoose.connection.close();
}