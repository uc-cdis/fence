# Fence and Google

## Data Access

Fence can issue short lived, cloud native credentials to access data in various cloud storage services. For Google, there are a handful of data access methods:

1. Signed URLs
2. Temporary Service Account Credentials
3. Google Account Linking and Service Account Registration

We'll talk about each one of those in-depth here. First though, an overall look at the Fence+Google architecture.

### Fence -> cirrus -> Google

We have a library that wraps Google's public API called [cirrus](https://github.com/uc-cdis/cirrus). Our design is such that fence does not hit Google's API directly, but goes through cirrus. For all of cirrus's features to work, a very specific setup is required, which is detailed in cirrus's README.

Essentially, cirrus requires a Google Cloud Identity account (for group management) and
Google Cloud Platform project(s). In order to automate group management in Google Cloud Identity with cirrus, you must go through a manual process of allowing API access and delegating a specific service account from a Google Cloud Platform project to have group management authority. Details can be found in cirrus's README.

Once cirrus has access to manage groups and is configured with proper credentials to access a Google Cloud Platform project, you can use the Python library within Fence.

### Data Access Google Architecture

To support the 3 methods of access mentioned above, we have a generic architecture that provides linkage between an end-user and rights to access a Google storage bucket.

That architecture involves Google's concept of **groups** and use of their **IAM Policies** in the Google Cloud Platform. The following diagram shows the layers between the user themselves and the bucket.

![Google Access Architecture](docs/images/g_architecture.png)

Working backwards from the Google Bucket itself, we have a **Google Bucket Access Group**, which, as you probably guessed, provides access to the bucket. That group is assigned a **role** on the Google **resource** (the Google Bucket). **Roles** provide a set of permissions (like read privileges). The combinations of those roles on the bucket, become the bucket's **Policy**. You can read more about Google's IAM terms and concepts in [their docs](https://cloud.google.com/iam/docs/overview).

The important thing to note here is that *any* entity inside that Google Bucket Access Group (GBAG) will have whatever role/permissions were set between the GBAG and the Bucket itself with Google's IAM.

So, now we can control access to the bucket by adding and removing entities from the GBAG (instead of having to modify the bucket's IAM Policy all the time). This is, in fact, the way Google recommends dynamically controlling access to a bucket.

#### Groups within Groups

Google groups contain **members** (another Google term) and a Google group can be a member. So, this allows you to nest Google groups, e.g. have groups inside of other groups.

So a more representative diagram of the structures that allow users to get access to the buckets may look something like this:

![Representative Google Access Architecture](docs/images/rep_g_architecture.png)

#### User's Proxy Group

Each user is associated with a *single* Google Group (a 1:1 relationship). This group serves as a sort of proxy to get access. Thus, we've dubbed this a **User Proxy Group**. It contains all the entities that should have identical data access as the user themselves.

This means that other Google accounts (like a personal email) can be in this User Proxy Group. That capability is used in the **Google Account Linking and Service Account Registration** access method.

The User Proxy Groups also allows a central location for Google Service Accounts that are given the same access as the user (which are used for the **Temporary Service Account Credentials** and **Signed URL** access method).

### Crash Course: Fence Clients

Fence supports OpenID Connect / Oauth2 flows to allow outside applications to request access to user's data and do things on their behalf. Users **must** consent to this before the outside application is given access.

The Google Access methods mentioned above all require special client scopes (which allow the client to ask the user for this access), and the user must consent to the client using these methods.

The scopes that allow access to these methods are also available for individual users without going through an outside application. This means that users themselves are able to hit these endpoints to get access via the 3 different methods.

> NOTE: When these docs talks about `clients` accessing data, it's reasonable to assume that this means both `clients` and `users` themselves. Much of the algorithms behave similarly if the user themselves were to request access without going through an outside application.

### Temporary Service Account Credentials

Fence allows clients (and users themselves) to generate temporary credentials which they can use in Google's Cloud Platform to access data that the user has access to. This is done by using Google's **Service Accounts** and generating a **Service Account Key** to provide to the client. This key will allow the client to authenticate as that service account (which is controlled by Fence).

Each client (AKA outside application) that a user consents to get access through will get their own **Client Service Account** that is associated directly with a given user. In other works, there's a 1:many relationship between a user and their Client Service Accounts.

This allows clients to manage their temporary credentials without the chance of interfering with another client's. Fence provides capability to create and delete these keys through its API.

Each Client Service Account is a member in the User's Proxy Group, meaning it has the same access that the user themselves have.

![Temporary Service Account Credentials](docs/images/g_sa_creds.png)

> WARNING: By default, Google Service Account Keys have an expiration of 10 years. To create a more manageable and secure expiration you must manually "expire" the keys by deleting them with a cronjob (once they are alive longer than a configured expiration). Fence's command line tool `fence-create` has a function for expiring keys that you should run on a schedule. Check out `fence-create google-manage-keys --help`

### Google Account Linking and Service Account Registration

> TODO

![Google Account Linking](docs/images/g_accnt_link.png)
![Google Account Linking After Expiration](docs/images/g_accnt_link_2.png)
