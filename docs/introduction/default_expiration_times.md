## Default Expiration Times in Fence

Table contains various artifacts in fence that have temporary lifetimes and their default values.

> NOTE: "SA" in the below table stands for Service Account

| Name                                 | Lifetime     | Extendable? | Maximum Lifetime      | Details
|--------------------------------------|--------------|-------------|-----------------------|------------------------------------------------------------------------------------------|
| Access Token                         | 20 minutes   | TRUE        | Life of Refresh Token |                                                                                          |
| Refresh Token                        | 30 days      | FALSE       | N/A                   |                                                                                          |
| User's SA Account Access             | 7 days       | TRUE        | N/A                   | Access to data (e.g. length it stays in the proxy group). Can optionally provide an expiration less than 7 days                                 |
| User's Google Account Access         | 1 day        | TRUE        | N/A                   | After AuthN, how long we associate a Google email with the given user. Can optionally provide an expiration less than 1 day                    |
| User's Google Account Linkage        | Indefinite   | N/A         | N/A                   | Can optionally provide an expiration less than 1 hour                                    |
| Google Signed URL                    | Up to 1 hour | FALSE       | N/A                   | Can optionally provide an expiration less than 1 hour                                    |
| AWS Signed URL                       | Up to 1 hour | FALSE       | N/A                   | Obtained by an oauth client through /credentials/google                                  |
| Client SA (for User) Key             | 10 days      | FALSE       | N/A                   | Obtained by the user themselves for temp access. Can optionally provide an expiration less than 10 days                              |
| User Primary SA Key                  | 10 days      | FALSE       | N/A                   | Used for Google URL signing                                                              |
| User Primary SA Key for URL Signing  | 30 days      | FALSE       | N/A                   |                                                                                          |
| Sliding Session Window               | 15 minutes   | TRUE        | 8 hours               | access_token cookies get generated automatically when expired if session is still active |
