# Description:
This register functionality enables a registration page for users to provide basic information before "being added to a preconfigured group". Registration means that a user provides their name, organization, and email, in order to gain some predefined permissions (i.e. to be automatically added to a preconfigured Arborist group). This functionality adds the registration form itself along with an admin endpoint to list registered users and their information. Register Users is an optional feature. The user information provided during registration IS NOT VALIDATED IN ANY WAY currently. The registration page is not customizable at the moment

# How to enable:
- Set up a useryaml that has a GROUP with a policy (for example: "registered_users" with "data_upload" policy)
- Your test user should not be in this group
- Set up and run your Arborist
- Run usersync
- Put the name of the group in fence config's REGISTERED_USERS_GROUP; also set fence REGISTER_USERS_ON to true.
- Look in the Fence db and confirm that your test user is not registered (he has no registration_info block in his additional_info column)
- Look in Arborist db and confirm that your test user is not part of the group and does not have the group's policies
- Set up and run your Fence, which is talking to your Arborist
- Log in. You should be redirected to the registration form!
- Register.
- Check Arborist db and confirm that now your test user IS part of the group and DOES have the group's policies.
- Check Fence db and confirm that the registration info you entered is now in the additional_info column.
- Log out. Log in again. There should be no redirect to the registration form.
- You can hit /user/register directly to re-register.
- Now log in with a user that is an admin. Hit the /user/admin/register endpoint. You should see user's registration info.
