# Alexa PHP Endpoint

## What is this?
This project is a PHP library meant to be used with the [Alexa Skill Builder](https://developer.amazon.com/blogs/alexa/post/02d828b6-3144-46ea-9b4c-5ed2cbfadb9c/announcing-new-alexa-skill-builder-beta-a-tool-for-creating-skills) to rapidly build Alexa skills without needing to jump into Java or set up a server that runs node.js.

Here's a simple Hello World skill made with it:
```php
<?php
// Include the library
require __DIR__ . '/alexa-endpoint/autoload.php';

// include the certificate check 
// this validates the request has been sent from alexa
require __DIR__ . '/certificate_check.php';

// Import classes
use MayBeTall\Alexa\Endpoint\Alexa;
use MayBeTall\Alexa\Endpoint\User;

// Sets everything up.
Alexa::init();

// User launched the skill (Alexa launch Hello World).
Alexa::enters(function() {
    // Say something and close the app
    Alexa::say('Hello world!');
});

// User triggered the 'HelloWorldIntent' intent from the Skill Builder
User::triggered('HelloWorldIntent', function() {
    // Say something and close the app
    Alexa::say('Hello world!');
});

// User exited the skill.
Alexa::exits(function() {
    /**
     * Alexa will not say anything you send in reply, but it is important
     * to have this here because she will give an error message if we
     * don't acknowledge the skill's exit.
     */
});
```

## Documentation?
[Read the library's documentation here](https://github.com/MayBeTall/Alexa-PHP-Endpoint/tree/master/alexa-endpoint/docs).

## Can I use this for production environments?
This project is intended to be used by developers looking to have fun with Alexa. Maybe to intergrate her with some APIs, like Toggl's or Jira's. I wouldn't trust it for anything big - and I created it.

# Before we begin
## What do I need to get started?
You need:
1. An [Amazon Developer Account](https://developer.amazon.com/).
2. WAMP/MAMP/LAMP or a server.
3. A SSL (HTTPS) connection accessible from the internet.
4. Basic knowledge of PHP.
5. Basic understanding of the command line and how to run programs from it (for ngrok).

## I don't have an SSL certificate
No worries. We have a couple options.

### For developing locally with WAMP/MAMP/LAMP
You can use [ngrok](https://ngrok.com/download) to create an SSL connection that Amazon can connect to.

### For deploying on a server
You can get a real SSL certificate, or [create a self-signed certificate](http://www.selfsignedcertificate.com/) for development.

**Note:** I've never used that website. I literally just found it and thought it would be the easiest way for you do make one if needed.

# Getting started
Alright, we got everything we need? Good.

## Step 1: Getting the server ready
1. Download or clone this repo.
    * I hope you know how to do that.
2. Put the project in your enviroment.
    * I *really* hope you know how to do that.
3. Go to `HelloAlexa.php` with your browser.
    * You should see 'Application not authorized.' and that is great.
4. Set up SSL
    1. Download [ngrok](https://ngrok.com/download).
    2. Tell it to forward your local dev url. Check out their [documentation](https://ngrok.com/docs#expose)
    3. Go to the link ngrok supplies and try reaching `HelloAlexa.php` again.
        * See the same message? Good. We can move on.

## Step 2: Getting the Alexa skill ready
1. Follow step 1 in [this guide by Amazon on creating a skill](https://developer.amazon.com/public/solutions/alexa/alexa-skills-kit/content/fact-skill-1?&sc_channel=SEM&sc_campaign=Fact-Skill&sc_detail=Branded&sc_segment=Alexa-Tutorial&sc_publisher=Google&sc_country=WW&sc_medium=SEM_Fact-Skill_Branded_Alexa-Tutorial_Google_WW_0007&sc_trackingcode=0007&gclid=Cj0KEQjw0IvIBRDF0Yzq4qGE4IwBEiQATMQlMWafspWnRrEC-b08jKkU_oRJFN-c4JB1Ctk5BiAe5OEaAiME8P8HAQ).
    * The 'Name' and 'Invocation Name' can be anything they allow. I used `HelloWorld` and `hello world`.
2. Use the Skill Builder Beta.
3. Click 'Code Editor' on the left hand navigation.
4. Drag and drop `HelloAlexa.json`, or paste in the code from it.
5. Click "Save Model".
6. Click "Build Model"
7. Wait for it to build.

## Step 3: Connect the Alexa skill to the server
1. In the Skill Builder, go to Configuration.
2. Choose 'HTTPS'
3. Click a location
4. Paste the **HTTPS** url, ending with HelloAlexa.php.
5. Click next
6. Click 'My development endpoint is a sub-domain of a domain that has a wildcard certificate from a certificate authority' (or self-signed, if you did that).
7. Click next.

## Step 4: Test
1. Before we use Alexa, let's test using the 'Service Simulator'.
2. Type 'launch helloworld' (or whatever you used) and click 'Ask HelloWorld'
    * You should get back some JSON with 'Hi, what is your name?' somewhere inside.

## Step 5: Using the skill with Alexa
1. Your skill should be enabled now and your Alexa will have automatically installed the skill.
2. Say 'Alexa launch hello world'.
    * Follow prompts. Or don't.
3. Say 'Alexa, tell hello world my name is MayBeTall'
    * This jumps directly to the NameIntent, skipping the first prompt.
4. Say 'Alexa, tell hello world yes'
    * This just skips to the CoffeeIntent, which isn't meant to be jumped straight to, but we can anyways.

## Step 6: Make your own projects
Seriously, connect Alexa to the API of some website you love to use (like GitHub) and see how amazing it is to build your own intergrations. [Read the library's documentation here](https://github.com/MayBeTall/Alexa-PHP-Endpoint/tree/master/alexa-endpoint/docs).
