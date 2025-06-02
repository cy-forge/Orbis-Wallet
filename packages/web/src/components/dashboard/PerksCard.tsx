"use client";

import { Button } from "@/components/ui/button";
import { Card, CardTitle, CardHeader, CardContent } from "@/components/ui/card";
import type { FC } from "react";
import { SvgIcons } from "@/assets/SvgIcons";

interface PerksCardProps {
  perks:
    | {
        name: string;
        icon: FC;
        description: string;
        isUnlocked: boolean;
      }[]
    | null;
}

export function PerksCard({ perks }: PerksCardProps) {
  return (
    <Card className="w-full max-w-[436px] border-[#EDEFF3] bg-white dark:bg-[#0A1D1C] dark:border-[#314140] min-h-[537px]">
      <CardHeader className="flex flex-row justify-between">
        <CardTitle className="font-normal text-[28px]">
          <h2>Perks</h2>
        </CardTitle>
        <Button variant="secondary" className="dark:bg-[#314140]">
          View All
        </Button>
      </CardHeader>
      <CardContent
        className={`w-full h-full flex-column items-center ${
          !perks ? "my-auto" : ""
        }`}
      >
        {perks && (
          <div className="flex flex-col gap-3">
            {perks.map((perk) => {
              const Icon = perk.icon;
              return (
                <div className="flex flex-row gap-5 w-full py-4 px-4 gap-6 flex flex-col border bg-[#F7F9FF] border-[#EDEFF3] dark:bg-[#0A1D1C] dark:border-[#314140] rounded-lg items-center justify-center">
                  <div>
                    <Icon />
                  </div>
                  <div>
                    <h3>{perk.name}</h3>
                    <p className="text-sm">{perk.description}</p>
                  </div>
                  <Button
                    disabled={!perk.isUnlocked}
                    onClick={() => {}}
                    className="ml-auto"
                  >
                    Claim
                  </Button>
                </div>
              );
            })}
          </div>
        )}

        {/* If No Perks */}
        {!perks && (
          <div className="w-full py-6 px-16 gap-6 flex flex-col border bg-[#F7F9FF] border-[#EDEFF3] dark:bg-[#0A1D1C] dark:border-[#314140] rounded-lg items-center justify-center">
            <div>{SvgIcons["perksIconPlaceholder"]()}</div>
            <p>You Are Not Eligible For Perks Yet</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
