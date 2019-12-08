var express=require('express');
var router=express.Router();
var mongoose=require('mongoose');
var Book=require('../models/Book.js');
var passport=require('passport');
require('../config/passport')(passport);


/*Get All Books*/


router.get('/',passport.authenticate('jwt',{session:false}),function(req,res, next){
    var token=getToken(req.headers);
    if(token){
        Book.find(function(err,products){
            if(err){
                return next(err);
            }
            res.json(products);
            return null
 });    
    }else{
        return res.status(403).send({success:false,msg:'Unauthorized'})
    }
})


/*save book*/

router.post('/',passport.authenticate('jwt',{session:false}),function(req,res, next){
    var token=getToken(req.headers);
    if(token){
              Book.create(req.body,function(err,post){
                 if(err){
               return next(err); }
                     res.json(post);
                    });                    
    }else{
        return res.status(403).send({success:false,msg:'Unauthorized'})
    }
});


var getToken=function(headers){
    if(headers && headers.authorization){
        var parted=headers.authorization.split(' ');
        if(parted.length === 2){
            return parted[1];
        }else{
            return null
        }
    }else{
        return null;
    }
}

module.exports=router;