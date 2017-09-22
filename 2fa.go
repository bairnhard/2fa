package main

// 2fa = two factor authentication service

import (
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/ttacon/libphonenumber"

	"github.com/gin-gonic/gin"
)

// const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const capletters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const smalletters = "abcdefghijklmnopqrstuvwxyz"
const nums = "0123456789"
const symbols = "!@#$%^&*()-_=+,.?/:;{}[]`~"

type Result struct { //this is how the token looks like
	Token  string    `json:"token"`
	Expiry time.Time `json:"expiry"`
}

type SMS4amsg struct {
	Messages []struct {
		Recipients []struct {
			Dst string `json:"dst"`
		} `json:"recipients"`
		Text string `json:"text"`
	} `json:"messages"`
}

/* type SMS4amsg struct { //sms message struct
	Messages struct {
		Text       string `json:"text"`
		Recipients struct {
			Dst string `json:"dst"`
		} `json:"recipients"`
	} `json:"messages"`
}
*/

func main() {

	log.Println(time.Now(), "2fa started")

	router := gin.Default()

	router.GET("/token", maketoken) //token generator

	router.GET("/send", sendmessage) //send token via SMS4A

	router.Run()
}

func sendmessage(dest *gin.Context) {

	//SMS4A Credentials
	url := "https://sms4a.retarus.com/rest/v1/"
	rUser := "bernhard.hecker@retarus.de"
	rPwd := ".Retarus1"
	data := []byte(rUser + ":" + rPwd)
	rCred := base64.StdEncoding.EncodeToString(data) //encoded credentials
	fmt.Println(rCred)

	//Query Parameter and Number Handling
	destnum, _ := dest.GetQuery("dest") //destination number

	destnumvalid, err := libphonenumber.Parse(destnum, "DE") //validate phone number
	if err != nil {
		log.Println(time.Now(), err)
	}

	// formattedNum := libphonenumber.Format(destnumvalid, libphonenumber.INTERNATIONAL)

	i := libphonenumber.GetNumberType(destnumvalid)

	if i != libphonenumber.MOBILE {
		log.Println(time.Now(), "Not Mobile Number: ", destnumvalid)
	}

	//here we should either have a valid mobile number or leave the show...

	//is retarus online?
	status, err := http.Get(url + "version")
	if err != nil {
		log.Println(time.Now(), err)
	}
	defer status.Body.Close()

	// fmt.Println(status)
	// fmt.Println(destnum)
	dest.String(200, "%v", status)

	//http post message
	var msg SMS4amsg

	msg = SMS4amsg{messages: {text: "hello", destnum: {dst: destnum}}}

	dest.IndentedJSON(200, msg)

	client := &http.Client{}

	req, err := http.NewRequest("POST", url+"jobs", nil)
	if err != nil {
		log.Println(time.Now(), err)
	}
	req.SetBasicAuth(rUser, rPwd)

	resp, err := client.Do(req)
	if err != nil {
		log.Println(time.Now(), err)
	}
	fmt.Println("request :", resp)

	defer req.Body.Close()
}

func maketoken(q *gin.Context) {

	qlen, _ := q.GetQuery("length") //how long should it be
	qtype, _ := q.GetQuery("type")  //what kind of token do we want to have?

	var LetterBytes string

	switch qtype {
	case "string":
		LetterBytes = capletters + smalletters

	case "lstring":
		LetterBytes = smalletters

	case "ustring":
		LetterBytes = capletters
	case "numbers":
		LetterBytes = nums
	case "symbol":
		LetterBytes = symbols + smalletters + capletters
	}

	tokenlength, err := strconv.Atoi(qlen)
	if err != nil {
		log.Println(time.Now(), "Incorrect length query parameter: ", err)
	}

	//tests
	fmt.Println("len: ", tokenlength)
	fmt.Println("type: ", qtype)
	fmt.Println("LetterBytes", LetterBytes)
	// const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	var ergebnis []Result
	ergebnis = make([]Result, 10)

	for loop := 0; loop < 10; loop++ {

		b := make([]byte, tokenlength)
		for i := range b {
			b[i] = LetterBytes[rand.Intn(len(LetterBytes))]

		}
		str := string(b[:])
		exp := time.Now().Add(time.Minute * 5)
		ergebnis[loop] = Result{str, exp}

	}
	q.IndentedJSON(200, ergebnis)
}
