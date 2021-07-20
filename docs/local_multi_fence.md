## How to set up two local Fences

> This document currently describes how to locally run two of the same Fence,
> with different configurations/runscripts/databases only, in order to test
> multi-Fence setups. The next step is to document how to run two different
> versions of Fence locally. I have not tried, but the general procedure
> should go like this: Check out a separate copy of Fence, create a separate
> virtual environment, install, maybe adjust config, then proceed as below.

So you want two Fences! Let's call them main-Fence (the terminal Fence, the
client Fence) and other-Fence (the upstream Fence, the IdP Fence). Let's assume
that right now you have main-Fence set up, but not other-Fence.

1. Make another config file. I have named mine other-fence-config.yaml.
   - Save it somewhere other than the default config directory where your
     default fence config lives. Otherwise the config code will complain.
1. Make another database. I have named mine other_fence.
1. In the other-config:
   - set the BASE_URL to use a different port than does your main-Fence.
   - set the DB to your other-database.
   - set the default IdP to whatever you want. (Sadly, I have only tested with Google.)
   - set SESSION_COOKIE_NAME to something different from that of main-Fence,
     otherwise since both are on localhost the two Fences will eat each other's
     session tokens and there will be state errors on login.
1. Now you have to register main-Fence as a client to other-Fence.
   - fence-create will first look for a FENCE_DB environment variable and then
     look at the config. I don't think fence-create supports passing a config
     file on the command line, so let's just go with the envvar.
     Set FENCE_DB to other_fence.
   - From other-Fence, run:
     `fence-create client-create --client mainfence --urls
     'http://localhost:8080/user/login/fence/login' --username mainfence
     --auto-approve`
     (Adapt to your port and your preferences. The port should be
     that of main-Fence. You might need to remove the `/user` depending
     on your setup.)
   - (It _is_ necessary however that your client is an auto-approve client,
     because the "show consent screen" code is not equipped to deal with
     the redirect in this setup.)
   - OK. Check that your other-database has this client in it, and then put the
     new credentials into your main-Fence config.
1. Duplicate your runscript and name the duplicate other-runscript.py. Edit the
   port number to whatever your other-Fence is using.
   - If you have been using your own runscript and it is ancient, make sure to
     update it agaist run.py. The config/init code was updated mid-2021.
1. Do whatever setup you need for your other-Fence's upstream IdP.
1. Run your main Fence and run your other Fence!
   For other-Fence your command will look something like this:
   `[poetry run] python run_other_way.py --config_path other-fence-config.yaml`
1. Try: hit http://mainfence[/user]/login/fence
